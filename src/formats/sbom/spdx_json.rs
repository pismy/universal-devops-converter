//! SPDX JSON, spec versions 2.2 and 2.3.
//!
//! ```json
//! {
//!   "spdxVersion": "SPDX-2.3",
//!   "dataLicense": "CC0-1.0",
//!   "SPDXID": "SPDXRef-DOCUMENT",
//!   "name": "acme-api",
//!   "documentNamespace": "https://acme.example/spdx/acme-api",
//!   "creationInfo": { "created": "2026-06-26T12:00:00Z", "creators": ["Tool: syft-1.4.1"] },
//!   "packages": [
//!     { "SPDXID": "SPDXRef-Package-lodash", "name": "lodash", "versionInfo": "4.17.21",
//!       "downloadLocation": "NOASSERTION", "licenseDeclared": "MIT",
//!       "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
//!                           "referenceLocator": "pkg:npm/lodash@4.17.21" } ] }
//!   ],
//!   "relationships": [
//!     { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-lodash",
//!       "relationshipType": "DESCRIBES" }
//!   ]
//! }
//! ```
//!
//! Three things separate SPDX from CycloneDX, and each one costs something:
//!
//! - **Identifiers are constrained.** An SPDX id is `SPDXRef-` followed by
//!   letters, digits, dots and dashes. A CycloneDX `bom-ref` is usually a
//!   package URL, full of `:`, `/` and `@`. So writing SPDX *renames* every
//!   element and rewrites the relationship graph against the new names —
//!   reusing the CycloneDX refs would produce a document no SPDX tool accepts.
//! - **Licences are expressions, not free text.** SPDX accepts an SPDX
//!   expression or `NOASSERTION`. A licence CycloneDX recorded only by name has
//!   no valid form here, so it becomes `NOASSERTION` and is reported.
//! - **`creationInfo.created` is required.** Reading the clock would break the
//!   byte-stability the project guarantees, so the timestamp comes from the
//!   source and otherwise falls back to a fixed epoch, with a notice.
//!
//! Version differences are narrow but sharp. 2.2 requires `documentNamespace`
//! on the document and `copyrightText`, `licenseConcluded` and `licenseDeclared`
//! on every package, which 2.3 made optional — those are always written, with
//! `NOASSERTION` standing in, so one output satisfies either. In the other
//! direction, `primaryPackagePurpose` only exists from 2.3, and the 2.2 schema
//! forbids unknown properties, so writing it into a 2.2 document would
//! invalidate the whole file. It is omitted there.

use std::collections::HashMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::sbom::{
    Component, ComponentKind, Dependency, ExternalReference, Hash, License, SbomDoc, SpecOrigin,
    Tool,
};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "spdx-json";
const FAMILY: &str = "spdx";
const FALLBACK_VERSION: &str = "SPDX-2.3";

/// SPDX's stand-in for "nobody has determined this".
const NOASSERTION: &str = "NOASSERTION";

/// Used when the source carries no creation time. Deliberately recognizable:
/// 1970 reads as "not measured", where a plausible date would pass for real.
const UNKNOWN_TIME: &str = "1970-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawDocument {
    #[serde(default, rename = "spdxVersion")]
    spdx_version: Option<String>,
    #[serde(default, rename = "SPDXID")]
    spdx_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "documentNamespace")]
    document_namespace: Option<String>,
    #[serde(default, rename = "creationInfo")]
    creation_info: Option<RawCreationInfo>,
    #[serde(default)]
    packages: Vec<RawPackage>,
    #[serde(default)]
    relationships: Vec<RawRelationship>,
    #[serde(default)]
    files: Vec<serde_json::Value>,
    #[serde(default)]
    snippets: Vec<serde_json::Value>,
    #[serde(default, rename = "documentDescribes")]
    document_describes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawCreationInfo {
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    creators: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    #[serde(default, rename = "SPDXID")]
    spdx_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "versionInfo")]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
    #[serde(default)]
    originator: Option<String>,
    #[serde(default, rename = "copyrightText")]
    copyright: Option<String>,
    #[serde(default, rename = "licenseDeclared")]
    license_declared: Option<String>,
    #[serde(default, rename = "licenseConcluded")]
    license_concluded: Option<String>,
    #[serde(default)]
    checksums: Vec<RawChecksum>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<RawExternalRef>,
    #[serde(default, rename = "primaryPackagePurpose")]
    purpose: Option<String>,
    #[serde(default, rename = "downloadLocation")]
    download_location: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawChecksum {
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default, rename = "checksumValue")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawExternalRef {
    #[serde(default, rename = "referenceCategory")]
    category: Option<String>,
    #[serde(default, rename = "referenceType")]
    kind: Option<String>,
    #[serde(default, rename = "referenceLocator")]
    locator: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRelationship {
    #[serde(default, rename = "spdxElementId")]
    from: Option<String>,
    #[serde(default, rename = "relatedSpdxElement")]
    to: Option<String>,
    #[serde(default, rename = "relationshipType")]
    kind: Option<String>,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let raw: RawDocument = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    let version = raw.spdx_version.clone().ok_or_else(|| {
        Error::parse(
            FORMAT,
            "no `spdxVersion` — this does not look like an SPDX document",
        )
    })?;
    if !version.starts_with("SPDX-2") {
        return Err(Error::parse(
            FORMAT,
            format!(
                "`{version}` is not SPDX 2.x. SPDX 3 replaced the flat document with an RDF graph \
                 and is a different format, not a newer version of this one"
            ),
        ));
    }

    let document_id = raw
        .spdx_id
        .clone()
        .unwrap_or_else(|| "SPDXRef-DOCUMENT".into());
    let mut doc = SbomDoc {
        spec: Some(SpecOrigin::new(FAMILY, version)),
        document_id: raw.document_namespace.clone(),
        timestamp: raw.creation_info.as_ref().and_then(|c| c.created.clone()),
        tools: raw
            .creation_info
            .as_ref()
            .map(|c| read_tools(&c.creators))
            .unwrap_or_default(),
        ..Default::default()
    };

    let mut named_only = 0usize;
    for package in &raw.packages {
        doc.components.push(read_package(package, &mut named_only));
    }

    // What the document is *about*: whatever it DESCRIBES.
    let described: Vec<&str> = raw
        .relationships
        .iter()
        .filter(|r| {
            r.kind.as_deref() == Some("DESCRIBES") && r.from.as_deref() == Some(&document_id)
        })
        .filter_map(|r| r.to.as_deref())
        .chain(raw.document_describes.iter().map(String::as_str))
        .collect();
    if let Some(subject) = described.first().and_then(|id| {
        doc.components
            .iter()
            .position(|c| c.bom_ref.as_deref() == Some(*id))
    }) {
        doc.subject = Some(doc.components.remove(subject));
    }

    // Only DEPENDS_ON maps onto the pivot's graph. SPDX defines dozens of
    // relationship types; the rest are a richer statement than a bill of
    // materials pivot can hold.
    let mut other_relationships = 0usize;
    for relationship in &raw.relationships {
        match relationship.kind.as_deref() {
            Some("DEPENDS_ON") => {
                if let (Some(from), Some(to)) = (&relationship.from, &relationship.to) {
                    match doc.dependencies.iter_mut().find(|d| d.bom_ref == *from) {
                        Some(existing) => existing.depends_on.push(to.clone()),
                        None => doc.dependencies.push(Dependency {
                            bom_ref: from.clone(),
                            depends_on: vec![to.clone()],
                        }),
                    }
                }
            }
            Some("DESCRIBES") | Some("DESCRIBED_BY") | None => {}
            Some(_) => other_relationships += 1,
        }
    }

    if named_only > 0 {
        log::debug!("spdx-json: {named_only} package(s) had no SPDX licence expression");
    }
    if other_relationships > 0 {
        ctx.lossy(format!(
            "spdx-json: {other_relationships} relationship(s) other than DEPENDS_ON were dropped; \
             the pivot models a dependency graph, not SPDX's full relationship vocabulary"
        ));
    }
    if !raw.files.is_empty() {
        ctx.lossy(format!(
            "spdx-json: {} file entr(ies) were dropped; the pivot lists packages",
            raw.files.len()
        ));
    }
    if !raw.snippets.is_empty() {
        ctx.lossy("spdx-json: snippets were dropped");
    }
    let _ = raw.name;

    doc.sort();
    Ok(Doc::Sbom(Box::new(doc)))
}

fn read_package(raw: &RawPackage, named_only: &mut usize) -> Component {
    let mut component = Component::new(raw.name.clone().unwrap_or_default());
    component.bom_ref = raw.spdx_id.clone();
    component.version = raw.version.clone();
    component.description = raw
        .description
        .clone()
        .or_else(|| raw.summary.clone())
        .filter(|d| !d.is_empty() && d != NOASSERTION);
    component.supplier = strip_actor(raw.supplier.as_deref());
    component.author = strip_actor(raw.originator.as_deref());
    component.copyright = raw
        .copyright
        .clone()
        .filter(|c| !c.is_empty() && c != NOASSERTION && c != "NONE");
    component.kind = raw
        .purpose
        .as_deref()
        .and_then(purpose_to_kind)
        .unwrap_or_default();

    // `licenseDeclared` is what the package says about itself, which is the
    // closer analogue of a CycloneDX licence; `licenseConcluded` is the
    // auditor's verdict.
    let license = raw
        .license_declared
        .clone()
        .filter(|l| usable_license(l))
        .or_else(|| raw.license_concluded.clone().filter(|l| usable_license(l)));
    if let Some(license) = license {
        // A bare identifier is an id; anything with an operator is an
        // expression, and flattening the two would turn a choice into a claim.
        if license.contains(' ') {
            component.licenses.push(License::Expression(license));
        } else {
            component.licenses.push(License::Id(license));
        }
    } else {
        *named_only += 1;
    }

    component.hashes = raw
        .checksums
        .iter()
        .filter_map(|checksum| {
            Some(Hash::new(
                checksum.algorithm.as_deref()?,
                checksum.value.clone()?,
            ))
        })
        .collect();

    for reference in &raw.external_refs {
        match (reference.kind.as_deref(), reference.locator.as_deref()) {
            (Some("purl"), Some(locator)) => component.purl = Some(locator.to_string()),
            (Some(kind), Some(locator)) if kind.starts_with("cpe") => {
                component.cpe = Some(locator.to_string())
            }
            (Some(kind), Some(locator)) => component.external_references.push(ExternalReference {
                kind: reference
                    .category
                    .clone()
                    .unwrap_or_else(|| kind.to_string()),
                url: locator.to_string(),
                comment: None,
            }),
            _ => {}
        }
    }
    if let Some(homepage) = raw.homepage.as_deref().filter(|h| usable_license(h)) {
        component.external_references.push(ExternalReference {
            kind: "website".into(),
            url: homepage.to_string(),
            comment: None,
        });
    }
    let _ = &raw.download_location;

    component
}

/// SPDX writes actors as `Organization: Acme` or `Person: Ada`.
fn strip_actor(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw == NOASSERTION {
        return None;
    }
    Some(match raw.split_once(':') {
        Some((prefix, rest)) if matches!(prefix.trim(), "Organization" | "Person" | "Tool") => {
            rest.trim().to_string()
        }
        _ => raw.to_string(),
    })
}

fn usable_license(raw: &str) -> bool {
    !raw.is_empty() && raw != NOASSERTION && raw != "NONE"
}

/// `creators` entries look like `Tool: syft-1.4.1`.
fn read_tools(creators: &[String]) -> Vec<Tool> {
    creators
        .iter()
        .filter_map(|creator| {
            let rest = creator.strip_prefix("Tool:")?.trim();
            let (name, version) = match rest.rsplit_once('-') {
                Some((name, version))
                    if version.chars().next().is_some_and(|c| c.is_ascii_digit()) =>
                {
                    (name.to_string(), Some(version.to_string()))
                }
                _ => (rest.to_string(), None),
            };
            Some(Tool {
                name,
                version,
                vendor: None,
            })
        })
        .collect()
}

fn purpose_to_kind(purpose: &str) -> Option<ComponentKind> {
    Some(match purpose {
        "APPLICATION" => ComponentKind::Application,
        "FRAMEWORK" => ComponentKind::Framework,
        "LIBRARY" => ComponentKind::Library,
        "CONTAINER" => ComponentKind::Container,
        "OPERATING_SYSTEM" => ComponentKind::OperatingSystem,
        "DEVICE" => ComponentKind::Device,
        "FIRMWARE" => ComponentKind::Firmware,
        "FILE" => ComponentKind::File,
        _ => return None,
    })
}

fn kind_to_purpose(kind: ComponentKind) -> Option<&'static str> {
    Some(match kind {
        ComponentKind::Application => "APPLICATION",
        ComponentKind::Framework => "FRAMEWORK",
        ComponentKind::Library => "LIBRARY",
        ComponentKind::Container => "CONTAINER",
        ComponentKind::OperatingSystem => "OPERATING_SYSTEM",
        ComponentKind::Device => "DEVICE",
        ComponentKind::Firmware => "FIRMWARE",
        ComponentKind::File => "FILE",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OutDocument<'a> {
    #[serde(rename = "spdxVersion")]
    spdx_version: &'a str,
    #[serde(rename = "dataLicense")]
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: &'a str,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: OutCreationInfo,
    packages: Vec<OutPackage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relationships: Vec<OutRelationship>,
}

#[derive(Debug, Serialize)]
struct OutCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OutPackage<'a> {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: &'a str,
    #[serde(rename = "versionInfo", skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(rename = "downloadLocation")]
    download_location: &'static str,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(rename = "licenseConcluded")]
    license_concluded: &'static str,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "copyrightText")]
    copyright: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    originator: Option<String>,
    #[serde(
        rename = "primaryPackagePurpose",
        skip_serializing_if = "Option::is_none"
    )]
    purpose: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<OutChecksum<'a>>,
    #[serde(rename = "externalRefs", skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<OutExternalRef<'a>>,
}

#[derive(Debug, Serialize)]
struct OutChecksum<'a> {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    value: &'a str,
}

#[derive(Debug, Serialize)]
struct OutExternalRef<'a> {
    #[serde(rename = "referenceCategory")]
    category: &'static str,
    #[serde(rename = "referenceType")]
    kind: &'static str,
    #[serde(rename = "referenceLocator")]
    locator: &'a str,
}

#[derive(Debug, Serialize)]
struct OutRelationship {
    #[serde(rename = "spdxElementId")]
    from: String,
    #[serde(rename = "relatedSpdxElement")]
    to: String,
    #[serde(rename = "relationshipType")]
    kind: &'static str,
}

const DOCUMENT_ID: &str = "SPDXRef-DOCUMENT";

/// Assigns every component an SPDX-legal identifier and remembers the mapping,
/// so relationships can be rewritten against the new names.
///
/// SPDX ids are `SPDXRef-` plus letters, digits, dots and dashes. A CycloneDX
/// `bom-ref` is typically a package URL, which is none of those — reusing it
/// would produce a document no SPDX tool accepts.
struct Identifiers {
    by_source: HashMap<String, String>,
    used: Vec<String>,
}

impl Identifiers {
    fn new() -> Self {
        Identifiers {
            by_source: HashMap::new(),
            used: vec![DOCUMENT_ID.to_string()],
        }
    }

    fn assign(&mut self, component: &Component) -> String {
        let source = component
            .bom_ref
            .clone()
            .unwrap_or_else(|| component.identity());
        if let Some(existing) = self.by_source.get(&source) {
            return existing.clone();
        }

        let base: String = component
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let base = base.trim_matches('-').to_string();
        let base = if base.is_empty() {
            "Package".into()
        } else {
            base
        };

        let mut candidate = format!("SPDXRef-{base}");
        let mut suffix = 1;
        while self.used.contains(&candidate) {
            suffix += 1;
            candidate = format!("SPDXRef-{base}-{suffix}");
        }

        self.used.push(candidate.clone());
        self.by_source.insert(source, candidate.clone());
        candidate
    }

    fn resolve(&self, source: &str) -> Option<&String> {
        self.by_source.get(source)
    }
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_sbom()?;

    let target = if ctx.version_requested() {
        normalize_version(ctx.version().unwrap_or(FALLBACK_VERSION))
    } else {
        doc.version_within(FAMILY)
            .map(normalize_version)
            .unwrap_or_else(|| normalize_version(ctx.version().unwrap_or(FALLBACK_VERSION)))
    };

    let created = doc.timestamp.clone().unwrap_or_else(|| {
        ctx.degraded(
            "spdx-json: the document requires a creation time and the source carried none; \
             1970-01-01T00:00:00Z is emitted so the output stays reproducible",
        );
        UNKNOWN_TIME.to_string()
    });

    let mut identifiers = Identifiers::new();
    let mut packages = Vec::with_capacity(doc.components.len() + 1);
    let mut relationships = Vec::new();
    let mut named_licenses = 0usize;

    if let Some(subject) = &doc.subject {
        let id = identifiers.assign(subject);
        relationships.push(OutRelationship {
            from: DOCUMENT_ID.to_string(),
            to: id.clone(),
            kind: "DESCRIBES",
        });
        packages.push(write_package(subject, id, &target, &mut named_licenses));
    }
    for component in &doc.components {
        let id = identifiers.assign(component);
        packages.push(write_package(component, id, &target, &mut named_licenses));
    }

    // Relationships are rewritten against the new names; an edge pointing at
    // something that is not in the document would be a dangling reference.
    let mut dangling = 0usize;
    for dependency in &doc.dependencies {
        let Some(from) = identifiers.resolve(&dependency.bom_ref) else {
            dangling += 1;
            continue;
        };
        for target_ref in &dependency.depends_on {
            match identifiers.resolve(target_ref) {
                Some(to) => relationships.push(OutRelationship {
                    from: from.clone(),
                    to: to.clone(),
                    kind: "DEPENDS_ON",
                }),
                None => dangling += 1,
            }
        }
    }

    if named_licenses > 0 {
        ctx.degraded(format!(
            "spdx-json: {named_licenses} licence(s) were recorded only by name, which is not a \
             valid SPDX expression, and became NOASSERTION"
        ));
    }
    if dangling > 0 {
        ctx.lossy(format!(
            "spdx-json: {dangling} dependency edge(s) pointed at something the document does not \
             list and were dropped"
        ));
    }

    let name = doc
        .subject
        .as_ref()
        .map(|s| s.name.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("SBOM");

    let document = OutDocument {
        spdx_version: &target,
        data_license: "CC0-1.0",
        spdx_id: DOCUMENT_ID,
        name,
        // Required, and must be unique per document. Derived from the source's
        // own namespace when it has one, and otherwise from the content — never
        // from a random value, which would change on every run.
        document_namespace: doc.document_id.clone().unwrap_or_else(|| {
            format!(
                "https://spdx.org/spdxdocs/{name}-{}",
                crate::hash::fingerprint(&[name, &created])
            )
        }),
        creation_info: OutCreationInfo {
            created,
            creators: vec![format!("Tool: udc-{}", env!("CARGO_PKG_VERSION"))],
        },
        packages,
        relationships,
    };

    serde_json::to_writer_pretty(&mut *out, &document).map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// Accept `2.3` as well as `SPDX-2.3`, since the CLI selector reads better
/// without the prefix.
fn normalize_version(raw: &str) -> String {
    if raw.starts_with("SPDX-") {
        raw.to_string()
    } else {
        format!("SPDX-{raw}")
    }
}

fn write_package<'a>(
    component: &'a Component,
    spdx_id: String,
    target: &str,
    named_licenses: &mut usize,
) -> OutPackage<'a> {
    // SPDX takes an expression or NOASSERTION; a licence known only by prose
    // has no legal form here.
    let declared = component
        .licenses
        .iter()
        .find_map(|license| match license {
            License::Id(id) => Some(id.clone()),
            License::Expression(expression) => Some(expression.clone()),
            License::Name(_) => None,
        })
        .unwrap_or_else(|| {
            if component
                .licenses
                .iter()
                .any(|l| matches!(l, License::Name(_)))
            {
                *named_licenses += 1;
            }
            NOASSERTION.to_string()
        });

    let mut external_refs = Vec::new();
    if let Some(purl) = component.purl.as_deref() {
        external_refs.push(OutExternalRef {
            category: "PACKAGE-MANAGER",
            kind: "purl",
            locator: purl,
        });
    }
    if let Some(cpe) = component.cpe.as_deref() {
        external_refs.push(OutExternalRef {
            category: "SECURITY",
            kind: "cpe23Type",
            locator: cpe,
        });
    }

    OutPackage {
        spdx_id,
        name: &component.name,
        version: component.version.as_deref(),
        // Required by both versions; the pivot does not model where a package
        // was fetched from.
        download_location: NOASSERTION,
        files_analyzed: false,
        license_concluded: NOASSERTION,
        license_declared: declared,
        copyright: component
            .copyright
            .clone()
            .unwrap_or_else(|| NOASSERTION.to_string()),
        description: component.description.as_deref(),
        supplier: component
            .supplier
            .as_deref()
            .map(|name| format!("Organization: {name}")),
        originator: component
            .author
            .as_deref()
            .map(|name| format!("Person: {name}")),
        // `primaryPackagePurpose` arrived in 2.3, and the 2.2 schema forbids
        // unknown properties — emitting it there invalidates the document.
        purpose: (target != "SPDX-2.2")
            .then(|| kind_to_purpose(component.kind))
            .flatten(),
        checksums: component
            .hashes
            .iter()
            .map(|hash| OutChecksum {
                // SPDX spells them without the dash: SHA256, not SHA-256.
                algorithm: hash.algorithm.replace('-', ""),
                value: &hash.value,
            })
            .collect(),
        external_refs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    fn parse(input: &str) -> (SbomDoc, Warnings) {
        let mut ctx = FormatCtx::new(Some("2.3"));
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Sbom(doc) => *doc,
            _ => panic!("expected a bill of materials"),
        };
        (doc, ctx.into_warnings())
    }

    fn render(doc: &SbomDoc, version: Option<&'static str>) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(version.or(Some("2.3")));
        ctx.set_version_requested(version.is_some());
        write(&Doc::Sbom(Box::new(doc.clone())), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    const DOCUMENT: &str = r#"{
      "spdxVersion": "SPDX-2.3",
      "dataLicense": "CC0-1.0",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "acme/api",
      "documentNamespace": "https://example.test/spdx/acme",
      "creationInfo": { "created": "2026-06-26T12:00:00Z", "creators": ["Tool: syft-1.4.1"] },
      "packages": [
        { "SPDXID": "SPDXRef-App", "name": "acme/api", "versionInfo": "1.2.3",
          "downloadLocation": "NOASSERTION", "primaryPackagePurpose": "APPLICATION" },
        { "SPDXID": "SPDXRef-Lodash", "name": "lodash", "versionInfo": "4.17.21",
          "downloadLocation": "NOASSERTION", "licenseDeclared": "MIT",
          "supplier": "Organization: OpenJS Foundation",
          "copyrightText": "Copyright JS Foundation",
          "checksums": [{ "algorithm": "SHA256", "checksumValue": "abc" }],
          "externalRefs": [{ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                             "referenceLocator": "pkg:npm/lodash@4.17.21" }] },
        { "SPDXID": "SPDXRef-Dual", "name": "dual", "downloadLocation": "NOASSERTION",
          "licenseDeclared": "Apache-2.0 OR MIT" }
      ],
      "relationships": [
        { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-App",
          "relationshipType": "DESCRIBES" },
        { "spdxElementId": "SPDXRef-App", "relatedSpdxElement": "SPDXRef-Lodash",
          "relationshipType": "DEPENDS_ON" },
        { "spdxElementId": "SPDXRef-Lodash", "relatedSpdxElement": "SPDXRef-App",
          "relationshipType": "CONTAINED_BY" }
      ]
    }"#;

    #[test]
    fn reads_packages_and_what_the_document_describes() {
        let (doc, _) = parse(DOCUMENT);
        assert_eq!(doc.version_within(FAMILY), Some("SPDX-2.3"));
        // DESCRIBES names the subject, which is not one of the listed
        // components.
        assert_eq!(doc.subject.as_ref().unwrap().name, "acme/api");
        assert_eq!(doc.components.len(), 2);

        let lodash = doc.components.iter().find(|c| c.name == "lodash").unwrap();
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        assert_eq!(lodash.supplier.as_deref(), Some("OpenJS Foundation"));
        assert_eq!(lodash.licenses, vec![License::Id("MIT".into())]);
        // SPDX writes SHA256; the pivot canonicalizes to CycloneDX's spelling
        // so a conversion in either direction produces a valid document.
        assert_eq!(lodash.hashes[0].algorithm, "SHA-256");
    }

    #[test]
    fn spdx_spelling_is_restored_on_the_way_out() {
        let (doc, _) = parse(DOCUMENT);
        let (json, _) = render(&doc, None);
        let lodash = json["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "lodash")
            .unwrap();
        assert_eq!(lodash["checksums"][0]["algorithm"], "SHA256");
    }

    #[test]
    fn an_expression_stays_an_expression() {
        let (doc, _) = parse(DOCUMENT);
        let dual = doc.components.iter().find(|c| c.name == "dual").unwrap();
        assert_eq!(
            dual.licenses,
            vec![License::Expression("Apache-2.0 OR MIT".into())]
        );
    }

    #[test]
    fn only_depends_on_becomes_a_dependency_and_the_rest_is_reported() {
        let (doc, warnings) = parse(DOCUMENT);
        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].depends_on, ["SPDXRef-Lodash"]);
        // CONTAINED_BY has no pivot equivalent.
        assert!(warnings
            .messages()
            .any(|m| m.contains("other than DEPENDS_ON")));
    }

    #[test]
    fn writing_renames_elements_and_rewrites_the_graph() {
        // A CycloneDX bom-ref is usually a package URL, which an SPDX id cannot
        // hold; reusing it would produce a document no SPDX tool accepts.
        let mut component = Component::new("lodash");
        component.bom_ref = Some("pkg:npm/lodash@4.17.21".into());
        let mut app = Component::new("acme/api");
        app.bom_ref = Some("acme-api".into());

        let doc = SbomDoc {
            subject: Some(app),
            components: vec![component],
            dependencies: vec![crate::model::sbom::Dependency {
                bom_ref: "acme-api".into(),
                depends_on: vec!["pkg:npm/lodash@4.17.21".into()],
            }],
            timestamp: Some("2026-06-26T12:00:00Z".into()),
            ..Default::default()
        };
        let (json, _) = render(&doc, None);

        let ids: Vec<&str> = json["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["SPDXID"].as_str().unwrap())
            .collect();
        assert!(ids.iter().all(|id| id.starts_with("SPDXRef-")), "{ids:?}");
        assert!(!ids.iter().any(|id| id.contains(':')), "{ids:?}");

        // And the edge points at the new names, not the old ones.
        let edge = json["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["relationshipType"] == "DEPENDS_ON")
            .unwrap();
        assert!(ids.contains(&edge["spdxElementId"].as_str().unwrap()));
        assert!(ids.contains(&edge["relatedSpdxElement"].as_str().unwrap()));
    }

    #[test]
    fn a_licence_known_only_by_name_becomes_noassertion() {
        let mut component = Component::new("odd");
        component
            .licenses
            .push(License::Name("A bespoke licence".into()));
        let (json, warnings) = render(
            &SbomDoc {
                components: vec![component],
                timestamp: Some("2026-06-26T12:00:00Z".into()),
                ..Default::default()
            },
            None,
        );

        assert_eq!(json["packages"][0]["licenseDeclared"], NOASSERTION);
        assert!(warnings.messages().any(|m| m.contains("only by name")));
    }

    #[test]
    fn a_2_3_only_field_is_not_written_into_a_2_2_document() {
        // The 2.2 schema forbids unknown properties, so emitting
        // primaryPackagePurpose there invalidates the whole file.
        let (doc, _) = parse(DOCUMENT);
        assert!(render(&doc, Some("2.3")).0["packages"][0]["primaryPackagePurpose"].is_string());
        assert!(render(&doc, Some("2.2")).0["packages"][0]["primaryPackagePurpose"].is_null());
    }

    #[test]
    fn an_absent_creation_time_is_reproducible_and_admitted() {
        let doc = SbomDoc {
            components: vec![Component::new("x")],
            ..Default::default()
        };
        let (json, warnings) = render(&doc, None);
        assert_eq!(json["creationInfo"]["created"], UNKNOWN_TIME);
        assert!(warnings.messages().any(|m| m.contains("creation time")));
        assert_eq!(
            json,
            render(&doc, None).0,
            "output must not depend on the clock"
        );
    }

    #[test]
    fn rejects_spdx_3_as_another_format() {
        let mut ctx = FormatCtx::new(Some("2.3"));
        let error = read(br#"{"spdxVersion":"SPDX-3.0","@graph":[]}"#, &mut ctx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("different format"), "{error}");
    }

    #[test]
    fn rejects_json_that_is_not_an_spdx_document() {
        let mut ctx = FormatCtx::new(Some("2.3"));
        assert!(read(br#"{"packages":[]}"#, &mut ctx).is_err());
    }
}
