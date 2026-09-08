//! SPDX 3.0 JSON-LD.
//!
//! Not a newer version of [`super::spdx_json`] — a different format that
//! happens to share a name, which is why it has its own id rather than
//! `spdx-json@3.0`. SPDX 2 is a document with `packages` and `relationships`
//! arrays; SPDX 3 is a **graph of elements**, each with its own IRI, and almost
//! everything that was a field is now an element or an edge:
//!
//! | SPDX 2 | SPDX 3 |
//! |---|---|
//! | `packages[]` | `software_Package` elements in `@graph` |
//! | `SPDXRef-Foo` | an IRI, e.g. `https://…/spdx/Foo` |
//! | `licenseDeclared: "MIT"` | a `simplelicensing_LicenseExpression` element, reached by a `hasDeclaredLicense` relationship |
//! | `checksums[]` | `Hash` elements under `verifiedUsing` |
//! | `relationships[].relationshipType: "DEPENDS_ON"` | `relationshipType: "dependsOn"` |
//!
//! That last row is the third spelling of the same vocabulary this project has
//! had to reconcile: `SHA-256` in CycloneDX, `SHA256` in SPDX 2, `sha256` in
//! SPDX 3. The pivot holds one, and each writer renders its own.
//!
//! Elements are addressed by IRI, so writing renames everything — the same
//! problem SPDX 2 posed with `SPDXRef-` ids, one step further.

use std::collections::HashMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::sbom::{
    Component, ComponentKind, Dependency, Hash, License, SbomDoc, SpecOrigin,
};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "spdx3-json";
const FAMILY: &str = "spdx3";
const CONTEXT: &str = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
const SPEC_VERSION: &str = "3.0.1";

/// Namespace for the IRIs this writer mints. Elements must be addressable, and
/// a document that invents them under a domain it does not own would be worse
/// than one under the specification's own.
const IRI_BASE: &str = "https://spdx.org/spdxdocs";

const UNKNOWN_TIME: &str = "1970-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default, rename = "@context")]
    context: Option<serde_json::Value>,
    #[serde(default, rename = "@graph")]
    graph: Vec<RawElement>,
}

#[derive(Debug, Deserialize)]
struct RawElement {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default, rename = "spdxId")]
    spdx_id: Option<String>,
    #[serde(default, rename = "@id")]
    node_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    summary: Option<String>,

    // software_Package
    #[serde(default, rename = "software_packageVersion")]
    package_version: Option<String>,
    #[serde(default, rename = "software_packageUrl")]
    package_url: Option<String>,
    #[serde(default, rename = "software_copyrightText")]
    copyright: Option<String>,
    #[serde(default, rename = "software_primaryPurpose")]
    primary_purpose: Option<String>,
    #[serde(default, rename = "verifiedUsing")]
    verified_using: Vec<RawIntegrity>,
    #[serde(default, rename = "originatedBy")]
    originated_by: Vec<String>,
    #[serde(default, rename = "suppliedBy")]
    supplied_by: Option<String>,

    // Relationship
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default, rename = "relationshipType")]
    relationship_type: Option<String>,

    // simplelicensing_LicenseExpression
    #[serde(default, rename = "simplelicensing_licenseExpression")]
    license_expression: Option<String>,

    // CreationInfo
    #[serde(default)]
    created: Option<String>,
    #[serde(default, rename = "specVersion")]
    spec_version: Option<String>,

    // SpdxDocument
    #[serde(default, rename = "rootElement")]
    root_element: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawIntegrity {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default, rename = "hashValue")]
    value: Option<String>,
}

impl RawElement {
    fn id(&self) -> Option<&str> {
        self.spdx_id.as_deref().or(self.node_id.as_deref())
    }
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let raw: RawFile = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    let context_is_spdx3 = raw
        .context
        .as_ref()
        .map(|c| c.to_string().contains("spdx.org/rdf/3."))
        .unwrap_or(false);
    if !context_is_spdx3 {
        return Err(Error::parse(
            FORMAT,
            "no SPDX 3 `@context` — this does not look like an SPDX 3 document",
        ));
    }
    if raw.graph.is_empty() {
        return Err(Error::parse(FORMAT, "the `@graph` is empty"));
    }

    // Licence expressions are elements; the packages point at them.
    let licenses: HashMap<&str, &str> = raw
        .graph
        .iter()
        .filter(|e| e.kind.as_deref() == Some("simplelicensing_LicenseExpression"))
        .filter_map(|e| Some((e.id()?, e.license_expression.as_deref()?)))
        .collect();

    let created = raw
        .graph
        .iter()
        .find(|e| e.kind.as_deref() == Some("CreationInfo"))
        .and_then(|e| e.created.clone());
    let spec_version = raw
        .graph
        .iter()
        .find(|e| e.kind.as_deref() == Some("CreationInfo"))
        .and_then(|e| e.spec_version.clone())
        .unwrap_or_else(|| SPEC_VERSION.to_string());

    let mut components: HashMap<String, Component> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for element in &raw.graph {
        if element.kind.as_deref() != Some("software_Package") {
            continue;
        }
        let Some(id) = element.id() else { continue };
        order.push(id.to_string());
        components.insert(id.to_string(), read_package(element));
    }

    // Relationships carry both the dependency graph and the licences.
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut roots: Vec<&str> = Vec::new();
    let mut ignored_relationships = 0usize;

    for element in &raw.graph {
        if element.kind.as_deref() == Some("SpdxDocument") {
            roots.extend(element.root_element.iter().map(String::as_str));
            continue;
        }
        if element.kind.as_deref() != Some("Relationship") {
            continue;
        }
        let (Some(from), Some(kind)) = (
            element.from.as_deref(),
            element.relationship_type.as_deref(),
        ) else {
            continue;
        };
        match kind {
            "dependsOn" => {
                let targets: Vec<String> = element.to.clone();
                match dependencies.iter_mut().find(|d| d.bom_ref == from) {
                    Some(existing) => existing.depends_on.extend(targets),
                    None => dependencies.push(Dependency {
                        bom_ref: from.to_string(),
                        depends_on: targets,
                    }),
                }
            }
            "hasDeclaredLicense" | "hasConcludedLicense" => {
                if let Some(component) = components.get_mut(from) {
                    if component.licenses.is_empty() {
                        for target in &element.to {
                            if let Some(expression) = licenses.get(target.as_str()) {
                                component.licenses.push(as_license(expression));
                            }
                        }
                    }
                }
            }
            "describes" => roots.extend(element.to.iter().map(String::as_str)),
            _ => ignored_relationships += 1,
        }
    }

    let mut doc = SbomDoc {
        spec: Some(SpecOrigin::new(FAMILY, spec_version)),
        timestamp: created,
        dependencies,
        ..Default::default()
    };

    let subject_id = roots.first().map(|id| id.to_string());
    for id in order {
        let Some(component) = components.remove(&id) else {
            continue;
        };
        if Some(&id) == subject_id.as_ref() {
            doc.subject = Some(component);
        } else {
            doc.components.push(component);
        }
    }

    if ignored_relationships > 0 {
        ctx.lossy(format!(
            "spdx3-json: {ignored_relationships} relationship(s) other than dependsOn and the \
             licence ones were dropped; the pivot models a dependency graph, not SPDX 3's full \
             relationship vocabulary"
        ));
    }

    doc.sort();
    Ok(Doc::Sbom(Box::new(doc)))
}

fn read_package(raw: &RawElement) -> Component {
    let mut component = Component::new(raw.name.clone().unwrap_or_default());
    component.bom_ref = raw.id().map(str::to_string);
    component.version = raw.package_version.clone();
    component.purl = raw.package_url.clone();
    component.description = raw
        .description
        .clone()
        .or_else(|| raw.summary.clone())
        .filter(|d| !d.is_empty());
    component.copyright = raw.copyright.clone().filter(|c| !c.is_empty());
    component.supplier = raw.supplied_by.clone();
    component.author = raw.originated_by.first().cloned();
    component.kind = raw
        .primary_purpose
        .as_deref()
        .and_then(purpose_to_kind)
        .unwrap_or_default();
    component.hashes = raw
        .verified_using
        .iter()
        .filter(|integrity| integrity.kind.as_deref() == Some("Hash"))
        .filter_map(|integrity| {
            Some(Hash::new(
                integrity.algorithm.as_deref()?,
                integrity.value.clone()?,
            ))
        })
        .collect();
    component
}

fn as_license(expression: &str) -> License {
    if expression.contains(' ') {
        License::Expression(expression.to_string())
    } else {
        License::Id(expression.to_string())
    }
}

/// SPDX 3 spells purposes in lowerCamelCase, where SPDX 2 shouted them.
fn purpose_to_kind(purpose: &str) -> Option<ComponentKind> {
    Some(match purpose {
        "application" => ComponentKind::Application,
        "framework" => ComponentKind::Framework,
        "library" => ComponentKind::Library,
        "container" => ComponentKind::Container,
        "operatingSystem" => ComponentKind::OperatingSystem,
        "device" => ComponentKind::Device,
        "firmware" => ComponentKind::Firmware,
        "file" => ComponentKind::File,
        _ => return None,
    })
}

fn kind_to_purpose(kind: ComponentKind) -> Option<&'static str> {
    Some(match kind {
        ComponentKind::Application => "application",
        ComponentKind::Framework => "framework",
        ComponentKind::Library => "library",
        ComponentKind::Container => "container",
        ComponentKind::OperatingSystem => "operatingSystem",
        ComponentKind::Device => "device",
        ComponentKind::Firmware => "firmware",
        ComponentKind::File => "file",
        _ => return None,
    })
}

/// The third spelling of the same vocabulary: CycloneDX writes `SHA-256`,
/// SPDX 2 `SHA256`, SPDX 3 `sha256`.
fn hash_algorithm(canonical: &str) -> Option<&'static str> {
    Some(match canonical {
        "MD5" => "md5",
        "SHA-1" => "sha1",
        "SHA-224" => "sha224",
        "SHA-256" => "sha256",
        "SHA-384" => "sha384",
        "SHA-512" => "sha512",
        "SHA3-256" => "sha3_256",
        "SHA3-384" => "sha3_384",
        "SHA3-512" => "sha3_512",
        "BLAKE2b-256" => "blake2b256",
        "BLAKE2b-384" => "blake2b384",
        "BLAKE2b-512" => "blake2b512",
        "BLAKE3" => "blake3",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OutFile {
    #[serde(rename = "@context")]
    context: &'static str,
    #[serde(rename = "@graph")]
    graph: Vec<serde_json::Value>,
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_sbom()?;

    let created = doc.timestamp.clone().unwrap_or_else(|| {
        ctx.degraded(
            "spdx3-json: the document requires a creation time and the source carried none; \
             1970-01-01T00:00:00Z is emitted so the output stays reproducible",
        );
        UNKNOWN_TIME.to_string()
    });

    let name = doc
        .subject
        .as_ref()
        .map(|s| s.name.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("sbom");
    let namespace = format!(
        "{IRI_BASE}/{}-{}",
        sanitize(name),
        crate::hash::fingerprint(&[name, &created])
    );

    let creation_info = "_:creationInfo";
    let mut graph = vec![serde_json::json!({
        "type": "CreationInfo",
        "@id": creation_info,
        "specVersion": SPEC_VERSION,
        "created": created,
        "createdBy": [format!("{namespace}/Agent-udc")],
    })];
    graph.push(serde_json::json!({
        "type": "Agent",
        "spdxId": format!("{namespace}/Agent-udc"),
        "creationInfo": creation_info,
        "name": format!("udc-{}", env!("CARGO_PKG_VERSION")),
    }));

    // Mint an IRI per component and remember it: relationships address elements
    // by IRI, and a `bom-ref` carried over from CycloneDX is not one.
    let mut iris: HashMap<String, String> = HashMap::new();
    let mut used: Vec<String> = Vec::new();
    let mut assign = |component: &Component| -> String {
        let source = component
            .bom_ref
            .clone()
            .unwrap_or_else(|| component.identity());
        if let Some(existing) = iris.get(&source) {
            return existing.clone();
        }
        let mut candidate = format!("{namespace}/{}", sanitize(&component.name));
        let mut suffix = 1;
        while used.contains(&candidate) {
            suffix += 1;
            candidate = format!("{namespace}/{}-{suffix}", sanitize(&component.name));
        }
        used.push(candidate.clone());
        iris.insert(source, candidate.clone());
        candidate
    };

    let mut ordered: Vec<(&Component, String)> = Vec::new();
    if let Some(subject) = &doc.subject {
        let iri = assign(subject);
        ordered.push((subject, iri));
    }
    for component in &doc.components {
        let iri = assign(component);
        ordered.push((component, iri));
    }

    let mut dropped_hashes = false;
    let mut named_licenses = 0usize;
    let mut license_elements = Vec::new();
    let mut relationships = Vec::new();

    // `suppliedBy` and `originatedBy` reference an `Agent` element, they are
    // not names. A person or organization therefore has to become an element of
    // its own before anything can point at it.
    let mut agents: HashMap<String, String> = HashMap::new();
    let mut agent_elements = Vec::new();
    let agent_for = |name: &str,
                     agents: &mut HashMap<String, String>,
                     elements: &mut Vec<serde_json::Value>|
     -> String {
        if let Some(existing) = agents.get(name) {
            return existing.clone();
        }
        let iri = format!("{namespace}/Agent-{}", sanitize(name));
        elements.push(serde_json::json!({
            "type": "Agent",
            "spdxId": iri,
            "creationInfo": creation_info,
            "name": name,
        }));
        agents.insert(name.to_string(), iri.clone());
        iri
    };

    for (index, (component, iri)) in ordered.iter().enumerate() {
        let hashes: Vec<serde_json::Value> = component
            .hashes
            .iter()
            .filter_map(|hash| {
                let algorithm = hash_algorithm(&hash.algorithm);
                if algorithm.is_none() {
                    dropped_hashes = true;
                }
                Some(serde_json::json!({
                    "type": "Hash",
                    "algorithm": algorithm?,
                    "hashValue": hash.value,
                }))
            })
            .collect();

        let mut package = serde_json::json!({
            "type": "software_Package",
            "spdxId": iri,
            "creationInfo": creation_info,
            "name": component.name,
        });
        let object = package.as_object_mut().expect("just built");
        if let Some(version) = &component.version {
            object.insert("software_packageVersion".into(), version.clone().into());
        }
        if let Some(purl) = &component.purl {
            object.insert("software_packageUrl".into(), purl.clone().into());
        }
        if let Some(description) = &component.description {
            object.insert("description".into(), description.clone().into());
        }
        if let Some(copyright) = &component.copyright {
            object.insert("software_copyrightText".into(), copyright.clone().into());
        }
        if let Some(supplier) = &component.supplier {
            let iri = agent_for(supplier, &mut agents, &mut agent_elements);
            object.insert("suppliedBy".into(), iri.into());
        }
        if let Some(author) = &component.author {
            let iri = agent_for(author, &mut agents, &mut agent_elements);
            object.insert("originatedBy".into(), vec![iri].into());
        }
        if let Some(purpose) = kind_to_purpose(component.kind) {
            object.insert("software_primaryPurpose".into(), purpose.into());
        }
        if !hashes.is_empty() {
            object.insert("verifiedUsing".into(), hashes.into());
        }
        graph.push(package);

        // A licence is an element reached by a relationship, not a field.
        if let Some(expression) = component.licenses.iter().find_map(|license| match license {
            License::Id(id) => Some(id.clone()),
            License::Expression(expression) => Some(expression.clone()),
            License::Name(_) => None,
        }) {
            let license_iri = format!("{namespace}/License-{index}");
            license_elements.push(serde_json::json!({
                "type": "simplelicensing_LicenseExpression",
                "spdxId": license_iri,
                "creationInfo": creation_info,
                "simplelicensing_licenseExpression": expression,
            }));
            relationships.push(serde_json::json!({
                "type": "Relationship",
                "spdxId": format!("{namespace}/Relationship-license-{index}"),
                "creationInfo": creation_info,
                "from": iri,
                "relationshipType": "hasDeclaredLicense",
                "to": [license_iri],
            }));
        } else if component
            .licenses
            .iter()
            .any(|l| matches!(l, License::Name(_)))
        {
            named_licenses += 1;
        }
    }

    let mut dangling = 0usize;
    for (index, dependency) in doc.dependencies.iter().enumerate() {
        let Some(from) = iris.get(&dependency.bom_ref) else {
            dangling += 1;
            continue;
        };
        let targets: Vec<String> = dependency
            .depends_on
            .iter()
            .filter_map(|target| iris.get(target).cloned())
            .collect();
        dangling += dependency.depends_on.len() - targets.len();
        if targets.is_empty() {
            continue;
        }
        relationships.push(serde_json::json!({
            "type": "Relationship",
            "spdxId": format!("{namespace}/Relationship-depends-{index}"),
            "creationInfo": creation_info,
            "from": from,
            "relationshipType": "dependsOn",
            "to": targets,
        }));
    }

    graph.extend(agent_elements);
    graph.extend(license_elements);
    graph.extend(relationships);
    graph.push(serde_json::json!({
        "type": "SpdxDocument",
        "spdxId": format!("{namespace}/Document"),
        "creationInfo": creation_info,
        "name": name,
        "profileConformance": ["core", "software"],
        "rootElement": ordered.first().map(|(_, iri)| vec![iri.clone()]).unwrap_or_default(),
    }));

    if named_licenses > 0 {
        ctx.degraded(format!(
            "spdx3-json: {named_licenses} licence(s) were recorded only by name, which is not a \
             licence expression, and were omitted"
        ));
    }
    if dropped_hashes {
        ctx.lossy("spdx3-json: hashes using an algorithm SPDX 3 does not define were dropped");
    }
    if dangling > 0 {
        ctx.lossy(format!(
            "spdx3-json: {dangling} dependency edge(s) pointed at something the document does not \
             list and were dropped"
        ));
    }

    serde_json::to_writer_pretty(
        &mut *out,
        &OutFile {
            context: CONTEXT,
            graph,
        },
    )
    .map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// An IRI segment: letters, digits, dots and dashes.
fn sanitize(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "element".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    fn parse(input: &str) -> (SbomDoc, Warnings) {
        let mut ctx = FormatCtx::new(Some(SPEC_VERSION));
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Sbom(doc) => *doc,
            _ => panic!("expected a bill of materials"),
        };
        (doc, ctx.into_warnings())
    }

    fn render(doc: &SbomDoc) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some(SPEC_VERSION));
        write(&Doc::Sbom(Box::new(doc.clone())), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    /// Elements of one type, in graph order.
    fn elements<'a>(json: &'a serde_json::Value, kind: &str) -> Vec<&'a serde_json::Value> {
        json["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == kind)
            .collect()
    }

    const GRAPH: &str = r#"{
      "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
      "@graph": [
        { "type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
          "created": "2026-06-26T12:00:00Z", "createdBy": ["https://acme.test/Agent-syft"] },
        { "type": "software_Package", "spdxId": "https://acme.test/api", "name": "acme/api",
          "software_packageVersion": "1.2.3", "software_primaryPurpose": "application" },
        { "type": "software_Package", "spdxId": "https://acme.test/lodash", "name": "lodash",
          "software_packageVersion": "4.17.21",
          "software_packageUrl": "pkg:npm/lodash@4.17.21",
          "software_primaryPurpose": "library",
          "verifiedUsing": [{ "type": "Hash", "algorithm": "sha256", "hashValue": "abc" }] },
        { "type": "simplelicensing_LicenseExpression", "spdxId": "https://acme.test/lic-mit",
          "simplelicensing_licenseExpression": "MIT" },
        { "type": "Relationship", "spdxId": "https://acme.test/r1",
          "from": "https://acme.test/lodash", "relationshipType": "hasDeclaredLicense",
          "to": ["https://acme.test/lic-mit"] },
        { "type": "Relationship", "spdxId": "https://acme.test/r2",
          "from": "https://acme.test/api", "relationshipType": "dependsOn",
          "to": ["https://acme.test/lodash"] },
        { "type": "Relationship", "spdxId": "https://acme.test/r3",
          "from": "https://acme.test/api", "relationshipType": "contains",
          "to": ["https://acme.test/lodash"] },
        { "type": "SpdxDocument", "spdxId": "https://acme.test/doc", "name": "acme/api",
          "rootElement": ["https://acme.test/api"] }
      ]
    }"#;

    #[test]
    fn reads_packages_out_of_the_graph() {
        let (doc, _) = parse(GRAPH);
        assert_eq!(doc.version_within(FAMILY), Some("3.0.1"));
        assert_eq!(doc.timestamp.as_deref(), Some("2026-06-26T12:00:00Z"));
        // rootElement names the subject; it is not one of the components.
        assert_eq!(doc.subject.as_ref().unwrap().name, "acme/api");
        assert_eq!(doc.components.len(), 1);

        let lodash = &doc.components[0];
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        // sha256 in SPDX 3, SHA-256 in the pivot.
        assert_eq!(lodash.hashes[0].algorithm, "SHA-256");
    }

    #[test]
    fn a_licence_is_an_element_reached_by_a_relationship() {
        // In SPDX 2 this was a string field; here it takes two hops.
        let (doc, _) = parse(GRAPH);
        assert_eq!(doc.components[0].licenses, vec![License::Id("MIT".into())]);
    }

    #[test]
    fn only_the_relationships_the_pivot_models_survive() {
        let (doc, warnings) = parse(GRAPH);
        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].depends_on, ["https://acme.test/lodash"]);
        // `contains` has no pivot equivalent.
        assert!(warnings
            .messages()
            .any(|m| m.contains("other than dependsOn")));
    }

    #[test]
    fn writing_mints_an_iri_for_every_element_and_rewrites_the_graph() {
        let (doc, _) = parse(GRAPH);
        let (json, _) = render(&doc);

        let packages = elements(&json, "software_Package");
        assert_eq!(packages.len(), 2);
        for package in &packages {
            let id = package["spdxId"].as_str().unwrap();
            assert!(id.starts_with("https://"), "{id}");
        }

        // The dependency edge points at the new IRIs, not the old ones.
        let depends = elements(&json, "Relationship")
            .into_iter()
            .find(|r| r["relationshipType"] == "dependsOn")
            .expect("the dependency survived");
        let ids: Vec<&str> = packages
            .iter()
            .map(|p| p["spdxId"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&depends["from"].as_str().unwrap()));
        assert!(ids.contains(&depends["to"][0].as_str().unwrap()));
    }

    #[test]
    fn a_licence_becomes_an_element_plus_a_relationship() {
        let (doc, _) = parse(GRAPH);
        let (json, _) = render(&doc);

        let licenses = elements(&json, "simplelicensing_LicenseExpression");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0]["simplelicensing_licenseExpression"], "MIT");
        assert!(elements(&json, "Relationship")
            .iter()
            .any(|r| r["relationshipType"] == "hasDeclaredLicense"));
    }

    #[test]
    fn a_supplier_becomes_an_agent_element_rather_than_a_string() {
        // `suppliedBy` references an Agent; a bare name makes the document
        // invalid, which is what the schema check caught.
        let mut component = Component::new("lodash");
        component.supplier = Some("OpenJS Foundation".into());
        let (json, _) = render(&SbomDoc {
            components: vec![component],
            timestamp: Some("2026-06-26T12:00:00Z".into()),
            ..Default::default()
        });

        let agents = elements(&json, "Agent");
        // The tool's own agent, plus the supplier's.
        assert!(agents.iter().any(|a| a["name"] == "OpenJS Foundation"));

        let package = elements(&json, "software_Package")[0];
        let supplier = package["suppliedBy"].as_str().unwrap();
        assert!(supplier.starts_with("https://"), "{supplier}");
    }

    #[test]
    fn the_hash_vocabulary_is_rendered_in_spdx_3_spelling() {
        // Third spelling of the same thing: SHA-256 / SHA256 / sha256.
        let mut component = Component::new("x");
        component.hashes.push(Hash::new("SHA-256", "abc"));
        let (json, _) = render(&SbomDoc {
            components: vec![component],
            timestamp: Some("2026-06-26T12:00:00Z".into()),
            ..Default::default()
        });
        assert_eq!(
            elements(&json, "software_Package")[0]["verifiedUsing"][0]["algorithm"],
            "sha256"
        );
    }

    #[test]
    fn round_trips_without_losing_a_package() {
        let (doc, _) = parse(GRAPH);
        let (json, _) = render(&doc);
        let (again, _) = parse(&serde_json::to_string(&json).unwrap());

        assert_eq!(again.components.len(), doc.components.len());
        assert_eq!(again.subject.as_ref().unwrap().name, "acme/api");
        assert_eq!(again.components[0].licenses, doc.components[0].licenses);
        assert_eq!(again.dependencies.len(), doc.dependencies.len());
    }

    #[test]
    fn an_absent_creation_time_is_reproducible() {
        let doc = SbomDoc {
            components: vec![Component::new("x")],
            ..Default::default()
        };
        let (json, warnings) = render(&doc);
        assert!(warnings.messages().any(|m| m.contains("creation time")));
        assert_eq!(json, render(&doc).0, "output must not depend on the clock");
    }

    #[test]
    fn rejects_spdx_2_which_is_a_different_format() {
        let mut ctx = FormatCtx::new(Some(SPEC_VERSION));
        assert!(read(
            br#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}"#,
            &mut ctx
        )
        .is_err());
    }

    #[test]
    fn rejects_an_empty_graph() {
        let mut ctx = FormatCtx::new(Some(SPEC_VERSION));
        assert!(read(
            br#"{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}"#,
            &mut ctx
        )
        .is_err());
    }
}
