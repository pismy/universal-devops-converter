//! CycloneDX XML, spec versions 1.4 through 1.6.
//!
//! The same model as the JSON serialization and the same pivot, so what is
//! written here is what [`super::cyclonedx_json`] would write — but the two
//! encodings differ in ways that matter to a reader:
//!
//! - **The spec version lives in the namespace**, not in a field.
//!   `xmlns="http://cyclonedx.org/schema/bom/1.6"` is the only place it appears,
//!   where JSON has an explicit `specVersion`.
//! - **Licences are a choice of shape.** `<licenses>` holds either `<license>`
//!   elements or a single `<expression>`, and the two mean different things —
//!   an expression is a choice, an id is a claim.
//! - **Dependencies nest.** `<dependency ref="a"><dependency ref="b"/></dependency>`
//!   says a depends on b, where JSON uses a flat `dependsOn` array.
//! - **Hashes put the algorithm in an attribute** and the digest in the text.
//!
//! Component-type narrowing works exactly as it does in JSON: a kind the target
//! version does not define would invalidate the whole document, so it is
//! written as `library` and reported.

use std::io::Write;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::sbom::{
    Component, ComponentKind, Dependency, ExternalReference, Hash, License, SbomDoc, SpecOrigin,
};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{attr, get_attr, local_name, xml_error, Attrs, XmlWriter};

const FORMAT: &str = "cyclonedx-xml";
const FAMILY: &str = "cyclonedx";
const FALLBACK_VERSION: &str = "1.5";
const NAMESPACE_PREFIX: &str = "http://cyclonedx.org/schema/bom/";

/// The spec version out of `xmlns="http://cyclonedx.org/schema/bom/1.6"`.
fn version_from_namespace(namespace: &str) -> Option<String> {
    namespace
        .strip_prefix(NAMESPACE_PREFIX)
        .map(|version| version.trim_end_matches('/').to_string())
        .filter(|version| !version.is_empty())
}

/// Where the reader currently is. CycloneDX XML reuses element names —
/// `<component>` appears under `<metadata>` and under `<components>`,
/// `<name>` under a component and under a supplier — so the path matters.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Scope {
    Root,
    Metadata,
    Components,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);

    let mut buffer = Vec::new();
    let mut doc = SbomDoc::default();
    let mut saw_root = false;

    let mut scope = Scope::Root;
    let mut component: Option<Component> = None;
    // Depth of nesting inside <components>, so a nested component is flattened
    // rather than lost.
    let mut nested = 0usize;
    let mut text = String::new();
    let mut path: Vec<String> = Vec::new();
    // Open <dependency ref> elements: the outer one depends on the inner ones.
    let mut dependency_stack: Vec<String> = Vec::new();
    let mut pending_hash: Option<String> = None;
    let mut pending_reference: Option<ExternalReference> = None;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?;

        match event {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                let empty = matches!(event, Event::Empty(_));
                let name = local_name(element);
                if !empty {
                    path.push(name.clone());
                }
                text.clear();

                match name.as_str() {
                    "bom" => {
                        saw_root = true;
                        doc.version = get_attr(element, "version").and_then(|v| v.parse().ok());
                        doc.document_id = get_attr(element, "serialNumber");
                        let namespace = get_attr(element, "xmlns")
                            .or_else(|| get_attr(element, "xsi:schemaLocation"))
                            .unwrap_or_default();
                        doc.spec = version_from_namespace(&namespace)
                            .map(|version| SpecOrigin::new(FAMILY, version));
                    }
                    "metadata" => scope = Scope::Metadata,
                    "components" if scope != Scope::Metadata => scope = Scope::Components,
                    "component" => {
                        if let Some(open) = component.replace(read_component_start(element)) {
                            // A component inside a component: flatten it, as the
                            // JSON reader does.
                            nested += 1;
                            doc.components.push(open);
                        }
                    }
                    "hash" => pending_hash = get_attr(element, "alg"),
                    "reference" => {
                        pending_reference = Some(ExternalReference {
                            kind: get_attr(element, "type").unwrap_or_else(|| "other".into()),
                            url: String::new(),
                            comment: None,
                        })
                    }
                    "dependency" => {
                        if let Some(reference) = get_attr(element, "ref") {
                            if let Some(parent) = dependency_stack.last() {
                                add_edge(&mut doc.dependencies, parent, &reference);
                            }
                            if !empty {
                                dependency_stack.push(reference);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(ref chunk) => {
                text = chunk
                    .unescape()
                    .map_err(|e| xml_error(FORMAT, e))?
                    .trim()
                    .to_string();
            }
            Event::End(ref element) => {
                let name = local_name(element);
                path.pop();

                match name.as_str() {
                    "metadata" => scope = Scope::Root,
                    "components" => scope = Scope::Root,
                    "dependency" => {
                        dependency_stack.pop();
                    }
                    "component" => {
                        if let Some(finished) = component.take() {
                            match scope {
                                Scope::Metadata => doc.subject = Some(finished),
                                _ => doc.components.push(finished),
                            }
                        }
                    }
                    "hash" => {
                        if let (Some(algorithm), Some(target)) =
                            (pending_hash.take(), component.as_mut())
                        {
                            target.hashes.push(Hash::new(&algorithm, text.clone()));
                        }
                    }
                    "reference" => {
                        if let (Some(reference), Some(target)) =
                            (pending_reference.take(), component.as_mut())
                        {
                            if !reference.url.is_empty() {
                                target.external_references.push(reference);
                            }
                        }
                    }
                    _ => {
                        apply_text(
                            &name,
                            &path,
                            &text,
                            component.as_mut(),
                            &mut doc,
                            &mut pending_reference,
                        );
                    }
                }
                text.clear();
            }
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <bom> root element — this does not look like a CycloneDX document",
        ));
    }
    if doc.spec.is_none() {
        return Err(Error::parse(
            FORMAT,
            "the <bom> element declares no CycloneDX namespace, so its spec version is unknown",
        ));
    }
    if nested > 0 {
        ctx.degraded(format!(
            "cyclonedx-xml: {nested} nested component(s) were flattened to the top level; the \
             pivot has no component tree, and the dependency graph carries the relationships"
        ));
    }

    doc.sort();
    Ok(Doc::Sbom(Box::new(doc)))
}

fn read_component_start(element: &BytesStart) -> Component {
    let mut component = Component::new(String::new());
    component.bom_ref = get_attr(element, "bom-ref");
    component.kind = get_attr(element, "type")
        .as_deref()
        .and_then(ComponentKind::parse)
        .unwrap_or_default();
    component
}

/// Assign a text node to whatever it belongs to. The enclosing path
/// disambiguates the names CycloneDX reuses — `<name>` under `<supplier>` is
/// not the component's name.
fn apply_text(
    name: &str,
    path: &[String],
    text: &str,
    component: Option<&mut Component>,
    doc: &mut SbomDoc,
    pending_reference: &mut Option<ExternalReference>,
) {
    if text.is_empty() {
        return;
    }
    let parent = path.last().map(String::as_str).unwrap_or("");

    if let Some(reference) = pending_reference.as_mut() {
        match name {
            "url" => reference.url = text.to_string(),
            "comment" => reference.comment = Some(text.to_string()),
            _ => {}
        }
        return;
    }

    let Some(component) = component else {
        if name == "timestamp" {
            doc.timestamp = Some(text.to_string());
        }
        return;
    };

    // The specific parents come first: CycloneDX reuses `<name>` for the
    // component, its supplier and a licence, and a catch-all arm ahead of them
    // would let a licence name overwrite the component's.
    match (name, parent) {
        ("name", "supplier") => component.supplier = Some(text.to_string()),
        ("name", "license") => component.licenses.push(License::Name(text.to_string())),
        ("id", "license") => component.licenses.push(License::Id(text.to_string())),
        ("name", _) => component.name = text.to_string(),
        ("version", "component") => component.version = Some(text.to_string()),
        ("group", _) => component.group = Some(text.to_string()),
        ("purl", _) => component.purl = Some(text.to_string()),
        ("cpe", _) => component.cpe = Some(text.to_string()),
        ("description", _) => component.description = Some(text.to_string()),
        ("scope", _) => component.scope = Some(text.to_string()),
        ("author", _) => component.author = Some(text.to_string()),
        ("publisher", _) => component.publisher = Some(text.to_string()),
        ("copyright", _) => component.copyright = Some(text.to_string()),
        // An expression is a choice between licences; an id is a claim about
        // one. Keeping them apart is the whole point of the pivot's enum.
        ("expression", _) => component
            .licenses
            .push(License::Expression(text.to_string())),
        _ => {}
    }
}

fn add_edge(dependencies: &mut Vec<Dependency>, from: &str, to: &str) {
    match dependencies.iter_mut().find(|d| d.bom_ref == from) {
        Some(existing) => {
            if !existing.depends_on.iter().any(|t| t == to) {
                existing.depends_on.push(to.to_string());
            }
        }
        None => dependencies.push(Dependency {
            bom_ref: from.to_string(),
            depends_on: vec![to.to_string()],
        }),
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_sbom()?;

    // Same rule as the JSON serialization: a BOM converted to CycloneDX keeps
    // the version it arrived as, whichever encoding it arrived in.
    let target = if ctx.version_requested() {
        ctx.version().unwrap_or(FALLBACK_VERSION).to_string()
    } else {
        doc.version_within(FAMILY)
            .map(str::to_string)
            .unwrap_or_else(|| ctx.version().unwrap_or(FALLBACK_VERSION).to_string())
    };

    let mut narrowed: Vec<&'static str> = Vec::new();
    let mut writer = XmlWriter::new(out);
    writer.declaration()?;

    let mut root = vec![attr("xmlns", format!("{NAMESPACE_PREFIX}{target}"))];
    if let Some(serial) = doc.document_id.as_deref().filter(|id| is_urn_uuid(id)) {
        root.push(attr("serialNumber", serial));
    }
    root.push(attr("version", doc.version.unwrap_or(1)));
    writer.open("bom", &root)?;

    if doc.timestamp.is_some() || doc.subject.is_some() {
        writer.open("metadata", &Attrs::new())?;
        if let Some(timestamp) = doc.timestamp.as_deref() {
            writer.text_element("timestamp", &Attrs::new(), timestamp)?;
        }
        if let Some(subject) = &doc.subject {
            write_component(&mut writer, subject, &target, &mut narrowed)?;
        }
        writer.close("metadata")?;
    }

    writer.open("components", &Attrs::new())?;
    for component in &doc.components {
        write_component(&mut writer, component, &target, &mut narrowed)?;
    }
    writer.close("components")?;

    if !doc.dependencies.is_empty() {
        writer.open("dependencies", &Attrs::new())?;
        for dependency in &doc.dependencies {
            if dependency.depends_on.is_empty() {
                writer.empty("dependency", &vec![attr("ref", &dependency.bom_ref)])?;
                continue;
            }
            writer.open("dependency", &vec![attr("ref", &dependency.bom_ref)])?;
            for target_ref in &dependency.depends_on {
                writer.empty("dependency", &vec![attr("ref", target_ref)])?;
            }
            writer.close("dependency")?;
        }
        writer.close("dependencies")?;
    }

    writer.close("bom")?;
    writer.finish()?;

    if doc.document_id.is_some() && !doc.document_id.as_deref().is_some_and(is_urn_uuid) {
        ctx.lossy(
            "cyclonedx-xml: the source document's identity is not a `urn:uuid:…` and could not be \
             carried over as a serial number",
        );
    }
    if doc
        .components
        .iter()
        .chain(doc.subject.iter())
        .flat_map(|c| &c.hashes)
        .any(|hash| !hash_is_writable(&hash.algorithm))
    {
        ctx.lossy(
            "cyclonedx-xml: hashes using an algorithm CycloneDX does not define were dropped; \
             emitting one would make the whole document invalid",
        );
    }
    for kind in &narrowed {
        ctx.degraded(format!(
            "cyclonedx-xml: `{kind}` is not a component type in {target}, so it was written as \
             `library`; emitting it would make the whole document invalid"
        ));
    }
    Ok(())
}

/// The hash algorithms CycloneDX accepts. SPDX's list is wider — MD2, MD6,
/// SHA-224 and ADLER32 have no CycloneDX equivalent — and an algorithm outside
/// this set invalidates the whole document, not just the one hash.
const KNOWN_HASH_ALGORITHMS: &[&str] = &[
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "BLAKE2b-256",
    "BLAKE2b-384",
    "BLAKE2b-512",
    "BLAKE3",
];

fn hash_is_writable(algorithm: &str) -> bool {
    KNOWN_HASH_ALGORITHMS.contains(&algorithm)
}

fn is_urn_uuid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("urn:uuid:") else {
        return false;
    };
    let groups: Vec<&str> = rest.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12] == groups.iter().map(|g| g.len()).collect::<Vec<_>>()[..]
        && groups.iter().all(|g| {
            g.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
}

fn write_component<W: Write>(
    writer: &mut XmlWriter<W>,
    component: &Component,
    target: &str,
    narrowed: &mut Vec<&'static str>,
) -> Result<()> {
    let (kind, was_narrowed) = component.kind.narrow_to(target);
    if was_narrowed && !narrowed.contains(&component.kind.as_str()) {
        narrowed.push(component.kind.as_str());
    }

    let mut attrs = vec![attr("type", kind.as_str())];
    if let Some(bom_ref) = component.bom_ref.as_deref() {
        attrs.push(attr("bom-ref", bom_ref));
    }
    writer.open("component", &attrs)?;

    // The schema fixes the order of a component's children, so this sequence is
    // not cosmetic: shuffling it produces a document that does not validate.
    if let Some(supplier) = component.supplier.as_deref() {
        writer.open("supplier", &Attrs::new())?;
        writer.text_element("name", &Attrs::new(), supplier)?;
        writer.close("supplier")?;
    }
    for (name, value) in [
        ("author", component.author.as_deref()),
        ("publisher", component.publisher.as_deref()),
        ("group", component.group.as_deref()),
    ] {
        if let Some(value) = value {
            writer.text_element(name, &Attrs::new(), value)?;
        }
    }
    writer.text_element("name", &Attrs::new(), &component.name)?;
    if let Some(version) = component.version.as_deref() {
        writer.text_element("version", &Attrs::new(), version)?;
    }
    if let Some(description) = component.description.as_deref() {
        writer.text_element("description", &Attrs::new(), description)?;
    }
    if let Some(scope) = component.scope.as_deref() {
        writer.text_element("scope", &Attrs::new(), scope)?;
    }

    let hashes: Vec<&crate::model::sbom::Hash> = component
        .hashes
        .iter()
        .filter(|hash| hash_is_writable(&hash.algorithm))
        .collect();
    if !hashes.is_empty() {
        writer.open("hashes", &Attrs::new())?;
        for hash in hashes {
            writer.text_element("hash", &vec![attr("alg", &hash.algorithm)], &hash.value)?;
        }
        writer.close("hashes")?;
    }

    if !component.licenses.is_empty() {
        writer.open("licenses", &Attrs::new())?;
        for license in &component.licenses {
            match license {
                // `<expression>` is a sibling of `<license>`, not a child.
                License::Expression(expression) => {
                    writer.text_element("expression", &Attrs::new(), expression)?
                }
                License::Id(id) => {
                    writer.open("license", &Attrs::new())?;
                    writer.text_element("id", &Attrs::new(), id)?;
                    writer.close("license")?;
                }
                License::Name(name) => {
                    writer.open("license", &Attrs::new())?;
                    writer.text_element("name", &Attrs::new(), name)?;
                    writer.close("license")?;
                }
            }
        }
        writer.close("licenses")?;
    }

    if let Some(copyright) = component.copyright.as_deref() {
        writer.text_element("copyright", &Attrs::new(), copyright)?;
    }
    if let Some(cpe) = component.cpe.as_deref() {
        writer.text_element("cpe", &Attrs::new(), cpe)?;
    }
    if let Some(purl) = component.purl.as_deref() {
        writer.text_element("purl", &Attrs::new(), purl)?;
    }

    if !component.external_references.is_empty() {
        writer.open("externalReferences", &Attrs::new())?;
        for reference in &component.external_references {
            writer.open("reference", &vec![attr("type", &reference.kind)])?;
            writer.text_element("url", &Attrs::new(), &reference.url)?;
            if let Some(comment) = reference.comment.as_deref() {
                writer.text_element("comment", &Attrs::new(), comment)?;
            }
            writer.close("reference")?;
        }
        writer.close("externalReferences")?;
    }

    writer.close("component")
}
