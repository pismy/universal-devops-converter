//! CycloneDX JSON, spec versions 1.4 through 1.6.
//!
//! ```json
//! {
//!   "bomFormat": "CycloneDX",
//!   "specVersion": "1.6",
//!   "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
//!   "version": 1,
//!   "metadata": { "timestamp": "…", "component": { "type": "application", "name": "acme" } },
//!   "components": [
//!     { "bom-ref": "pkg:npm/lodash@4.17.21", "type": "library", "name": "lodash",
//!       "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
//!       "licenses": [ { "license": { "id": "MIT" } } ] }
//!   ],
//!   "dependencies": [ { "ref": "…", "dependsOn": [ "…" ] } ]
//! }
//! ```
//!
//! CycloneDX calls itself backward compatible, and for the document shape it
//! is. The **enumerations are not**: `component.type` gained `platform`,
//! `device-driver`, `machine-learning-model` and `data` in 1.5, and
//! `cryptographic-asset` in 1.6. Writing one of those into a document declared
//! as 1.4 produces a file that validates nowhere — the consumer rejects all of
//! it, not the one component. So a kind the target version does not define is
//! narrowed to `library` and the narrowing is reported.
//!
//! Two more version facts shape this module:
//!
//! - **There is no CycloneDX JSON before 1.2.** Asking for an older version is
//!   refused rather than approximated.
//! - **Converting a BOM to CycloneDX keeps the version it arrived as**, unless
//!   the caller pinned one with `@`. Defaulting instead would silently
//!   downgrade every round trip (SPECS.md §3.4, rule 2).

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::sbom::{
    Component, ComponentKind, Dependency, ExternalReference, Hash, License, SbomDoc, SpecOrigin,
    Tool,
};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "cyclonedx-json";

/// Fallback when neither the caller nor the document says which version to
/// write. Matches the registry's default.
const FALLBACK_VERSION: &str = "1.5";

/// Spec lineage. A version is only carried over between documents of the same
/// family — `SPDX-2.3` is not a CycloneDX version.
const FAMILY: &str = "cyclonedx";

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawBom {
    #[serde(default, rename = "bomFormat")]
    bom_format: Option<String>,
    #[serde(default, rename = "specVersion")]
    spec_version: Option<String>,
    #[serde(default, rename = "serialNumber")]
    serial_number: Option<String>,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    metadata: Option<RawMetadata>,
    #[serde(default)]
    components: Vec<RawComponent>,
    #[serde(default)]
    dependencies: Vec<RawDependency>,
    /// Present from 1.4; the pivot has no room for it.
    #[serde(default)]
    vulnerabilities: Vec<serde_json::Value>,
    #[serde(default)]
    services: Vec<serde_json::Value>,
    #[serde(default)]
    compositions: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    component: Option<RawComponent>,
    #[serde(default)]
    tools: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawComponent {
    #[serde(default, rename = "bom-ref")]
    bom_ref: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    supplier: Option<RawNamed>,
    #[serde(default)]
    copyright: Option<String>,
    #[serde(default)]
    licenses: Vec<RawLicenseChoice>,
    #[serde(default)]
    hashes: Vec<RawHash>,
    #[serde(default, rename = "externalReferences")]
    external_references: Vec<RawExternalReference>,
    /// Nested components, which CycloneDX allows and the pivot flattens.
    #[serde(default)]
    components: Vec<RawComponent>,
}

#[derive(Debug, Deserialize)]
struct RawNamed {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLicenseChoice {
    #[serde(default)]
    license: Option<RawLicense>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLicense {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawHash {
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawExternalReference {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDependency {
    #[serde(default, rename = "ref")]
    bom_ref: Option<String>,
    #[serde(default, rename = "dependsOn")]
    depends_on: Vec<String>,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let bom: RawBom = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    if !bom
        .bom_format
        .as_deref()
        .is_some_and(|f| f.eq_ignore_ascii_case("CycloneDX"))
    {
        return Err(Error::parse(
            FORMAT,
            "no `bomFormat: \"CycloneDX\"` — this does not look like a CycloneDX document",
        ));
    }
    let spec_version = bom
        .spec_version
        .clone()
        .ok_or_else(|| Error::parse(FORMAT, "no `specVersion`, which CycloneDX requires"))?;

    let mut doc = SbomDoc {
        spec: Some(SpecOrigin::new(FAMILY, spec_version)),
        document_id: bom.serial_number,
        version: bom.version,
        timestamp: bom.metadata.as_ref().and_then(|m| m.timestamp.clone()),
        tools: read_tools(bom.metadata.as_ref().and_then(|m| m.tools.as_ref())),
        subject: bom
            .metadata
            .as_ref()
            .and_then(|m| m.component.as_ref())
            .map(read_component),
        ..Default::default()
    };

    let mut nested = 0usize;
    for raw in &bom.components {
        flatten(raw, &mut doc.components, &mut nested);
    }

    doc.dependencies = bom
        .dependencies
        .into_iter()
        .filter_map(|raw| {
            raw.bom_ref.map(|bom_ref| Dependency {
                bom_ref,
                depends_on: raw.depends_on,
            })
        })
        .collect();

    if nested > 0 {
        ctx.degraded(format!(
            "cyclonedx-json: {nested} nested component(s) were flattened to the top level; the \
             pivot has no component tree, and the dependency graph carries the relationships"
        ));
    }
    if !bom.vulnerabilities.is_empty() {
        ctx.lossy(format!(
            "cyclonedx-json: {} vulnerability record(s) were dropped; a bill of materials pivot \
             lists components, and vulnerabilities belong to the security category",
            bom.vulnerabilities.len()
        ));
    }
    if !bom.services.is_empty() {
        ctx.lossy(format!(
            "cyclonedx-json: {} service(s) were dropped; the pivot models components only",
            bom.services.len()
        ));
    }
    if !bom.compositions.is_empty() {
        ctx.lossy("cyclonedx-json: compositions (completeness statements) were dropped");
    }

    doc.sort();
    Ok(Doc::Sbom(Box::new(doc)))
}

/// CycloneDX lets a component contain components. The pivot is a flat list, so
/// the tree is flattened and the parent/child link is expressed as a
/// dependency, which is where a consumer looks for it anyway.
fn flatten(raw: &RawComponent, out: &mut Vec<Component>, nested: &mut usize) {
    out.push(read_component(raw));
    for child in &raw.components {
        *nested += 1;
        flatten(child, out, nested);
    }
}

fn read_component(raw: &RawComponent) -> Component {
    let mut component = Component::new(raw.name.clone().unwrap_or_default());
    component.bom_ref = raw.bom_ref.clone();
    component.kind = raw
        .kind
        .as_deref()
        .and_then(ComponentKind::parse)
        .unwrap_or_default();
    component.version = raw.version.clone();
    component.group = raw.group.clone();
    component.purl = raw.purl.clone();
    component.cpe = raw.cpe.clone();
    component.description = raw.description.clone();
    component.scope = raw.scope.clone();
    component.author = raw.author.clone();
    component.publisher = raw.publisher.clone();
    component.supplier = raw.supplier.as_ref().and_then(|s| s.name.clone());
    component.copyright = raw.copyright.clone();

    component.licenses = raw
        .licenses
        .iter()
        .filter_map(|choice| match (&choice.expression, &choice.license) {
            (Some(expression), _) if !expression.is_empty() => {
                Some(License::Expression(expression.clone()))
            }
            (_, Some(license)) => match (&license.id, &license.name) {
                (Some(id), _) if !id.is_empty() => Some(License::Id(id.clone())),
                (_, Some(name)) if !name.is_empty() => Some(License::Name(name.clone())),
                _ => None,
            },
            _ => None,
        })
        .collect();

    component.hashes = raw
        .hashes
        .iter()
        .filter_map(|hash| {
            Some(Hash {
                algorithm: hash.alg.clone()?,
                value: hash.content.clone()?,
            })
        })
        .collect();

    component.external_references = raw
        .external_references
        .iter()
        .filter_map(|reference| {
            Some(ExternalReference {
                kind: reference.kind.clone().unwrap_or_else(|| "other".into()),
                url: reference.url.clone()?,
                comment: reference.comment.clone(),
            })
        })
        .collect();

    component
}

/// `metadata.tools` is an array in 1.4 and an object with `components` in 1.5+.
fn read_tools(raw: Option<&serde_json::Value>) -> Vec<Tool> {
    let Some(raw) = raw else { return Vec::new() };
    let entries = match raw {
        serde_json::Value::Array(entries) => entries.clone(),
        serde_json::Value::Object(map) => map
            .get("components")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?.to_string();
            Some(Tool {
                name,
                version: entry
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                vendor: entry
                    .get("vendor")
                    .and_then(|v| v.as_str())
                    .or_else(|| entry.get("author").and_then(|v| v.as_str()))
                    .map(str::to_string),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OutBom<'a> {
    #[serde(rename = "$schema")]
    schema: String,
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'a str,
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<&'a str>,
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<OutMetadata<'a>>,
    components: Vec<OutComponent<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<OutDependency<'a>>,
}

#[derive(Debug, Serialize)]
struct OutMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<OutComponent<'a>>,
}

#[derive(Debug, Serialize)]
struct OutComponent<'a> {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    bom_ref: Option<&'a str>,
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpe: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<OutNamed<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    copyright: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<OutLicenseChoice<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<OutHash<'a>>,
    #[serde(rename = "externalReferences", skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<OutExternalReference<'a>>,
}

#[derive(Debug, Serialize)]
struct OutNamed<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum OutLicenseChoice<'a> {
    Expression { expression: &'a str },
    Named { license: OutLicense<'a> },
}

#[derive(Debug, Serialize)]
struct OutLicense<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct OutHash<'a> {
    alg: &'a str,
    content: &'a str,
}

#[derive(Debug, Serialize)]
struct OutExternalReference<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct OutDependency<'a> {
    #[serde(rename = "ref")]
    bom_ref: &'a str,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<&'a str>,
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_sbom()?;

    // Rule 2 of SPECS §3.4: a BOM converted to its own format keeps the version
    // it arrived as. The format default only applies when the source says
    // nothing and the caller did not ask.
    let target = if ctx.version_requested() {
        ctx.version().unwrap_or(FALLBACK_VERSION).to_string()
    } else {
        doc.version_within(FAMILY)
            .map(str::to_string)
            .unwrap_or_else(|| ctx.version().unwrap_or(FALLBACK_VERSION).to_string())
    };

    let mut narrowed: Vec<&'static str> = Vec::new();
    let components: Vec<OutComponent> = doc
        .components
        .iter()
        .map(|component| write_component(component, &target, &mut narrowed))
        .collect();
    let subject = doc
        .subject
        .as_ref()
        .map(|component| write_component(component, &target, &mut narrowed));

    for kind in &narrowed {
        ctx.degraded(format!(
            "cyclonedx-json: `{kind}` is not a component type in {target}, so it was written as \
             `library`; emitting it would make the whole document invalid"
        ));
    }
    if !doc.tools.is_empty() {
        ctx.lossy(
            "cyclonedx-json: the tools that produced the BOM were dropped; `metadata.tools` \
             changed shape between 1.4 and 1.5 and the pivot does not model the difference",
        );
    }

    // CycloneDX requires `urn:uuid:…`; SPDX's documentNamespace is any URI, so
    // carrying one straight over would produce a document that validates
    // nowhere. Omitting it is legal — the field is optional.
    let serial_number = doc.document_id.as_deref().filter(|id| is_urn_uuid(id));
    if doc.document_id.is_some() && serial_number.is_none() {
        ctx.lossy(
            "cyclonedx-json: the source document's identity is not a `urn:uuid:…` and could not \
             be carried over as a serial number",
        );
    }

    let has_metadata = doc.timestamp.is_some() || subject.is_some();
    let metadata = has_metadata.then_some(OutMetadata {
        timestamp: doc.timestamp.as_deref(),
        component: subject,
    });

    let bom = OutBom {
        schema: format!("http://cyclonedx.org/schema/bom-{target}.schema.json"),
        bom_format: "CycloneDX",
        spec_version: &target,
        serial_number,
        version: doc.version.unwrap_or(1),
        metadata,
        components,
        dependencies: doc
            .dependencies
            .iter()
            .map(|dependency| OutDependency {
                bom_ref: &dependency.bom_ref,
                depends_on: dependency.depends_on.iter().map(String::as_str).collect(),
            })
            .collect(),
    };

    serde_json::to_writer_pretty(&mut *out, &bom).map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// `urn:uuid:` followed by a canonical UUID, which is all CycloneDX accepts.
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

fn write_component<'a>(
    component: &'a Component,
    target: &str,
    narrowed: &mut Vec<&'static str>,
) -> OutComponent<'a> {
    let (kind, was_narrowed) = component.kind.narrow_to(target);
    if was_narrowed && !narrowed.contains(&component.kind.as_str()) {
        narrowed.push(component.kind.as_str());
    }

    OutComponent {
        bom_ref: component.bom_ref.as_deref(),
        kind: kind.as_str(),
        name: &component.name,
        version: component.version.as_deref(),
        group: component.group.as_deref(),
        purl: component.purl.as_deref(),
        cpe: component.cpe.as_deref(),
        description: component.description.as_deref(),
        scope: component.scope.as_deref(),
        author: component.author.as_deref(),
        publisher: component.publisher.as_deref(),
        supplier: component.supplier.as_deref().map(|name| OutNamed { name }),
        copyright: component.copyright.as_deref(),
        licenses: component
            .licenses
            .iter()
            .map(|license| match license {
                License::Expression(expression) => OutLicenseChoice::Expression { expression },
                License::Id(id) => OutLicenseChoice::Named {
                    license: OutLicense {
                        id: Some(id),
                        name: None,
                    },
                },
                License::Name(name) => OutLicenseChoice::Named {
                    license: OutLicense {
                        id: None,
                        name: Some(name),
                    },
                },
            })
            .collect(),
        hashes: component
            .hashes
            .iter()
            .map(|hash| OutHash {
                alg: &hash.algorithm,
                content: &hash.value,
            })
            .collect(),
        external_references: component
            .external_references
            .iter()
            .map(|reference| OutExternalReference {
                kind: &reference.kind,
                url: &reference.url,
                comment: reference.comment.as_deref(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    fn parse(input: &str) -> (SbomDoc, Warnings) {
        let mut ctx = FormatCtx::new(Some("1.5"));
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Sbom(doc) => *doc,
            _ => panic!("expected a bill of materials"),
        };
        (doc, ctx.into_warnings())
    }

    fn render(doc: &SbomDoc, version: Option<&'static str>) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(version.or(Some("1.5")));
        ctx.set_version_requested(version.is_some());
        write(&Doc::Sbom(Box::new(doc.clone())), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    const BOM: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version": 2,
      "metadata": {
        "timestamp": "2026-06-26T12:00:00Z",
        "component": { "type": "application", "name": "acme/api", "version": "1.2.3" }
      },
      "components": [
        { "bom-ref": "pkg:npm/lodash@4.17.21", "type": "library", "name": "lodash",
          "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
          "licenses": [{ "license": { "id": "MIT" } }],
          "hashes": [{ "alg": "SHA-256", "content": "abc" }] },
        { "bom-ref": "choice", "type": "library", "name": "dual",
          "licenses": [{ "expression": "Apache-2.0 OR MIT" }] },
        { "bom-ref": "keys", "type": "cryptographic-asset", "name": "tls-keypair" }
      ],
      "dependencies": [{ "ref": "pkg:npm/lodash@4.17.21", "dependsOn": [] }]
    }"#;

    #[test]
    fn reads_the_document_and_its_components() {
        let (doc, _) = parse(BOM);
        assert_eq!(doc.version_within(FAMILY), Some("1.6"));
        assert_eq!(doc.version, Some(2));
        assert_eq!(doc.subject.as_ref().unwrap().name, "acme/api");
        assert_eq!(doc.components.len(), 3);

        let lodash = doc.components.iter().find(|c| c.name == "lodash").unwrap();
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        assert_eq!(lodash.licenses, vec![License::Id("MIT".into())]);
        assert_eq!(lodash.hashes[0].algorithm, "SHA-256");
    }

    #[test]
    fn keeps_a_licence_expression_apart_from_an_identifier() {
        // `Apache-2.0 OR MIT` is a choice; flattening it to an id would turn it
        // into a claim that the component is Apache-2.0.
        let (doc, _) = parse(BOM);
        let dual = doc.components.iter().find(|c| c.name == "dual").unwrap();
        assert_eq!(
            dual.licenses,
            vec![License::Expression("Apache-2.0 OR MIT".into())]
        );
    }

    #[test]
    fn converting_to_its_own_format_keeps_the_source_version() {
        // Rule 2 of SPECS §3.4: without this, every round trip through the
        // format default would silently downgrade the document.
        let (doc, _) = parse(BOM);
        let (json, _) = render(&doc, None);
        assert_eq!(json["specVersion"], "1.6");
        assert_eq!(
            json["$schema"],
            "http://cyclonedx.org/schema/bom-1.6.schema.json"
        );
    }

    #[test]
    fn an_explicit_version_overrides_the_source() {
        let (doc, _) = parse(BOM);
        let (json, _) = render(&doc, Some("1.4"));
        assert_eq!(json["specVersion"], "1.4");
    }

    #[test]
    fn a_component_type_the_target_does_not_know_is_narrowed_and_reported() {
        let (doc, _) = parse(BOM);

        let (json, warnings) = render(&doc, Some("1.4"));
        let kinds: Vec<&str> = json["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        // 1.4 has no cryptographic-asset; emitting it would invalidate the
        // whole document rather than that one component.
        assert!(!kinds.contains(&"cryptographic-asset"), "{kinds:?}");
        assert!(warnings
            .messages()
            .any(|m| m.contains("`cryptographic-asset` is not a component type in 1.4")));

        // 1.6 knows it, so nothing is touched.
        let (json, warnings) = render(&doc, Some("1.6"));
        let kinds: Vec<&str> = json["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"cryptographic-asset"), "{kinds:?}");
        assert!(!warnings
            .messages()
            .any(|m| m.contains("not a component type")));
    }

    #[test]
    fn nested_components_are_flattened_and_reported() {
        let (doc, warnings) = parse(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.4","components":[
                 {"type":"library","name":"outer","components":[
                   {"type":"library","name":"inner"}]}]}"#,
        );
        let names: Vec<&str> = doc.components.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"outer") && names.contains(&"inner"),
            "{names:?}"
        );
        assert!(warnings.messages().any(|m| m.contains("flattened")));
    }

    #[test]
    fn vulnerabilities_are_reported_as_out_of_scope_rather_than_dropped_quietly() {
        let (_, warnings) = parse(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],
                "vulnerabilities":[{"id":"CVE-2024-1234"}]}"#,
        );
        assert!(warnings
            .messages()
            .any(|m| m.contains("vulnerability record")));
    }

    #[test]
    fn round_trips_without_losing_a_component() {
        let (doc, _) = parse(BOM);
        let (json, _) = render(&doc, None);
        let (again, _) = parse(&serde_json::to_string(&json).unwrap());

        assert_eq!(again.components.len(), doc.components.len());
        assert_eq!(again.spec, doc.spec);
        assert_eq!(again.document_id, doc.document_id);
        assert_eq!(again.components, doc.components);
    }

    #[test]
    fn an_identity_that_is_not_a_urn_uuid_is_dropped_rather_than_emitted() {
        // SPDX's documentNamespace is any URI; CycloneDX only accepts urn:uuid,
        // so carrying one straight over would invalidate the document.
        let doc = SbomDoc {
            document_id: Some("https://example.test/spdx/minimal".into()),
            ..Default::default()
        };
        let (json, warnings) = render(&doc, Some("1.5"));
        assert!(json.get("serialNumber").is_none());
        assert!(warnings.messages().any(|m| m.contains("urn:uuid")));

        let doc = SbomDoc {
            document_id: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".into()),
            ..Default::default()
        };
        let (json, _) = render(&doc, Some("1.5"));
        assert_eq!(
            json["serialNumber"],
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        );
    }

    #[test]
    fn rejects_json_that_is_not_a_bom() {
        let mut ctx = FormatCtx::new(Some("1.5"));
        assert!(read(br#"{"specVersion":"1.6","components":[]}"#, &mut ctx).is_err());
        assert!(read(br#"{"bomFormat":"CycloneDX"}"#, &mut ctx).is_err());
    }
}
