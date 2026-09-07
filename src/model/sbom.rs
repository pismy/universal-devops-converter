//! Pivot model for software bills of materials.
//!
//! Shaped after the intersection that actually travels between CycloneDX and
//! SPDX: what a component *is*, how it is identified, what it is licensed
//! under, and what it depends on. Everything either format adds beyond that —
//! CycloneDX's `evidence`, `pedigree` and `formulation`, SPDX's annotations and
//! its finer relationship types — is outside the pivot and is reported as lost
//! rather than silently dropped.
//!
//! The identity backbone is the **package URL**. `purl` is the one identifier
//! both formats carry, that survives a conversion in either direction, and that
//! two tools scanning the same project agree on. Names and versions are for
//! humans; `purl` is what a consumer matches on.

use crate::paths::PathMapper;

/// What a component is. CycloneDX's vocabulary, which is the wider of the two.
///
/// The list grew over time — `platform`, `device-driver`, `machine-learning-model`
/// and `data` arrived in 1.5, `cryptographic-asset` in 1.6 — so writing an older
/// spec version means narrowing the ones it does not know. See
/// [`ComponentKind::narrow_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComponentKind {
    Application,
    Framework,
    #[default]
    Library,
    Container,
    Platform,
    OperatingSystem,
    Device,
    DeviceDriver,
    Firmware,
    File,
    MachineLearningModel,
    Data,
    CryptographicAsset,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Application => "application",
            ComponentKind::Framework => "framework",
            ComponentKind::Library => "library",
            ComponentKind::Container => "container",
            ComponentKind::Platform => "platform",
            ComponentKind::OperatingSystem => "operating-system",
            ComponentKind::Device => "device",
            ComponentKind::DeviceDriver => "device-driver",
            ComponentKind::Firmware => "firmware",
            ComponentKind::File => "file",
            ComponentKind::MachineLearningModel => "machine-learning-model",
            ComponentKind::Data => "data",
            ComponentKind::CryptographicAsset => "cryptographic-asset",
        }
    }

    pub fn parse(raw: &str) -> Option<ComponentKind> {
        Some(match raw.trim().to_ascii_lowercase().as_str() {
            "application" => ComponentKind::Application,
            "framework" => ComponentKind::Framework,
            "library" => ComponentKind::Library,
            "container" => ComponentKind::Container,
            "platform" => ComponentKind::Platform,
            "operating-system" => ComponentKind::OperatingSystem,
            "device" => ComponentKind::Device,
            "device-driver" => ComponentKind::DeviceDriver,
            "firmware" => ComponentKind::Firmware,
            "file" => ComponentKind::File,
            "machine-learning-model" => ComponentKind::MachineLearningModel,
            "data" => ComponentKind::Data,
            "cryptographic-asset" => ComponentKind::CryptographicAsset,
            _ => return None,
        })
    }

    /// The CycloneDX spec version this kind first appeared in.
    fn since(self) -> &'static str {
        match self {
            ComponentKind::Platform
            | ComponentKind::DeviceDriver
            | ComponentKind::MachineLearningModel
            | ComponentKind::Data => "1.5",
            ComponentKind::CryptographicAsset => "1.6",
            _ => "1.0",
        }
    }

    /// This kind, or the nearest one `spec_version` knows.
    ///
    /// Writing a kind an older schema does not define produces a document that
    /// validates nowhere — the consumer rejects the whole file, not the one
    /// component. Falling back to `library` is a deliberate flattening rather
    /// than a claim that a cryptographic asset *is* a library, which is why the
    /// caller is expected to report it.
    pub fn narrow_to(self, spec_version: &str) -> (ComponentKind, bool) {
        if version_at_least(spec_version, self.since()) {
            (self, false)
        } else {
            (ComponentKind::Library, true)
        }
    }
}

/// `1.6 >= 1.5`, comparing the numeric parts rather than the strings — `1.10`
/// must not sort before `1.5`.
pub fn version_at_least(candidate: &str, minimum: &str) -> bool {
    let parts = |v: &str| {
        v.split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (a, b) = (parts(candidate), parts(minimum));
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        if left != right {
            return left > right;
        }
    }
    true
}

/// A licence, in whichever of the three shapes the source used.
///
/// They are kept apart on purpose: an SPDX *expression* (`MIT OR Apache-2.0`)
/// is not an id, and collapsing it to one would turn a choice into a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum License {
    /// An SPDX licence identifier, e.g. `Apache-2.0`.
    Id(String),
    /// A licence named in prose, when it has no SPDX id.
    Name(String),
    /// An SPDX licence expression, e.g. `MIT OR Apache-2.0`.
    Expression(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    /// Algorithm name, canonicalized on the way in.
    ///
    /// The formats disagree on spelling — SPDX writes `SHA256`, CycloneDX
    /// requires `SHA-256` — so keeping "whatever the source said" would make
    /// every SPDX → CycloneDX conversion produce a document that fails its own
    /// schema. One spelling in the pivot, and each writer renders its own.
    pub algorithm: String,
    pub value: String,
}

impl Hash {
    /// The canonical spelling: hyphenated, as CycloneDX writes it.
    pub fn canonical_algorithm(raw: &str) -> String {
        let upper = raw.trim().to_ascii_uppercase();
        match upper.as_str() {
            "SHA1" => "SHA-1".into(),
            "SHA224" => "SHA-224".into(),
            "SHA256" => "SHA-256".into(),
            "SHA384" => "SHA-384".into(),
            "SHA512" => "SHA-512".into(),
            "SHA3256" => "SHA3-256".into(),
            "SHA3384" => "SHA3-384".into(),
            "SHA3512" => "SHA3-512".into(),
            // BLAKE keeps a lowercase `b`, which uppercasing would eat.
            "BLAKE2B-256" | "BLAKE2B256" => "BLAKE2b-256".into(),
            "BLAKE2B-384" | "BLAKE2B384" => "BLAKE2b-384".into(),
            "BLAKE2B-512" | "BLAKE2B512" => "BLAKE2b-512".into(),
            _ => upper,
        }
    }

    pub fn new(algorithm: &str, value: impl Into<String>) -> Self {
        Hash {
            algorithm: Hash::canonical_algorithm(algorithm),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalReference {
    pub kind: String,
    pub url: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    /// Identifier other entries point at. Generated when the source has none,
    /// because the dependency graph is unusable without it.
    pub bom_ref: Option<String>,
    pub kind: ComponentKind,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    /// Package URL — the identifier that survives every conversion.
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub author: Option<String>,
    pub publisher: Option<String>,
    pub supplier: Option<String>,
    pub copyright: Option<String>,
    pub licenses: Vec<License>,
    pub hashes: Vec<Hash>,
    pub external_references: Vec<ExternalReference>,
}

impl Component {
    pub fn new(name: impl Into<String>) -> Self {
        Component {
            name: name.into(),
            ..Default::default()
        }
    }

    /// What this component *is*, for matching purposes: its `purl` when it has
    /// one, else its group, name and version.
    pub fn identity(&self) -> String {
        match &self.purl {
            Some(purl) => purl.clone(),
            None => format!(
                "{}{}@{}",
                self.group
                    .as_deref()
                    .map(|g| format!("{g}/"))
                    .unwrap_or_default(),
                self.name,
                self.version.as_deref().unwrap_or("")
            ),
        }
    }
}

/// One edge of the dependency graph: `bom_ref` depends on each of `depends_on`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dependency {
    pub bom_ref: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
}

/// The format family a document came from, and the spec version it declared.
///
/// A version only means something inside its family: `SPDX-2.3` is not a
/// CycloneDX version. Keeping the family alongside the version is what stops a
/// writer adopting a version from another lineage — which is exactly what a
/// bare `spec_version` field would have let it do the moment a second SBOM
/// format arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecOrigin {
    pub family: String,
    pub version: String,
}

impl SpecOrigin {
    pub fn new(family: impl Into<String>, version: impl Into<String>) -> Self {
        SpecOrigin {
            family: family.into(),
            version: version.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SbomDoc {
    /// Where the document came from, and in which spec version.
    ///
    /// Carried so that converting a BOM to its own format keeps the version it
    /// arrived as, instead of being silently rewritten to the format's default
    /// (SPECS.md §3.4, rule 2). Use [`SbomDoc::version_within`] to read it.
    pub spec: Option<SpecOrigin>,
    /// Identity of this particular document, as the source expressed it.
    ///
    /// CycloneDX calls it `serialNumber` and requires `urn:uuid:…`; SPDX calls
    /// it `documentNamespace` and accepts any URI. The pivot keeps whichever it
    /// was given, so a writer has to check the shape suits its own format
    /// rather than assuming — a `documentNamespace` is not a valid
    /// `serialNumber`.
    pub document_id: Option<String>,
    /// Revision of this serial number, 1 for a first issue.
    pub version: Option<u32>,
    pub timestamp: Option<String>,
    pub tools: Vec<Tool>,
    /// What the BOM is *about*, as opposed to what it lists.
    pub subject: Option<Component>,
    pub components: Vec<Component>,
    pub dependencies: Vec<Dependency>,
}

impl SbomDoc {
    /// The source spec version, but only when the source belongs to `family`.
    ///
    /// A CycloneDX writer handed an SPDX document gets `None` and falls back to
    /// its own default, rather than trying to write a BOM as version
    /// `SPDX-2.3`.
    pub fn version_within(&self, family: &str) -> Option<&str> {
        self.spec
            .as_ref()
            .filter(|origin| origin.family == family)
            .map(|origin| origin.version.as_str())
    }

    /// Fold another BOM in, matching components on their identity so the same
    /// package listed by two scanners is not listed twice.
    pub fn merge(&mut self, other: SbomDoc) {
        self.spec = self.spec.take().or(other.spec);
        self.document_id = self.document_id.take().or(other.document_id);
        self.version = self.version.or(other.version);
        self.timestamp = self.timestamp.take().or(other.timestamp);
        self.subject = self.subject.take().or(other.subject);

        for tool in other.tools {
            if !self.tools.contains(&tool) {
                self.tools.push(tool);
            }
        }
        for component in other.components {
            if !self
                .components
                .iter()
                .any(|existing| existing.identity() == component.identity())
            {
                self.components.push(component);
            }
        }
        for dependency in other.dependencies {
            match self
                .dependencies
                .iter_mut()
                .find(|d| d.bom_ref == dependency.bom_ref)
            {
                Some(existing) => {
                    for target in dependency.depends_on {
                        if !existing.depends_on.contains(&target) {
                            existing.depends_on.push(target);
                        }
                    }
                }
                None => self.dependencies.push(dependency),
            }
        }
    }

    /// A BOM's paths are `file` components and reference URLs; only the former
    /// mean anything to a repository.
    pub fn normalize_paths(&mut self, mapper: &PathMapper) {
        if mapper.is_noop() {
            return;
        }
        for component in &mut self.components {
            if component.kind == ComponentKind::File {
                component.name = mapper.map(&component.name);
            }
        }
    }

    /// Deterministic ordering, so a conversion is byte-stable across runs.
    pub fn sort(&mut self) {
        // `identity` allocates, so cache it rather than rebuilding the key on
        // every comparison.
        self.components.sort_by_cached_key(Component::identity);
        for component in &mut self.components {
            component.licenses.sort_by_key(|l| format!("{l:?}"));
            component
                .hashes
                .sort_by(|a, b| a.algorithm.cmp(&b.algorithm));
        }
        self.dependencies.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));
        for dependency in &mut self.dependencies {
            dependency.depends_on.sort();
            dependency.depends_on.dedup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically_not_alphabetically() {
        assert!(version_at_least("1.6", "1.5"));
        assert!(version_at_least("1.5", "1.5"));
        assert!(!version_at_least("1.4", "1.5"));
        // The case string comparison gets wrong.
        assert!(version_at_least("1.10", "1.5"));
    }

    #[test]
    fn a_kind_narrows_only_where_the_target_does_not_know_it() {
        assert_eq!(
            ComponentKind::CryptographicAsset.narrow_to("1.6"),
            (ComponentKind::CryptographicAsset, false)
        );
        // 1.5 has no cryptographic-asset; emitting it would invalidate the file.
        assert_eq!(
            ComponentKind::CryptographicAsset.narrow_to("1.5"),
            (ComponentKind::Library, true)
        );
        assert_eq!(
            ComponentKind::Platform.narrow_to("1.4"),
            (ComponentKind::Library, true)
        );
        // Kinds that have always existed are never touched.
        assert_eq!(
            ComponentKind::Container.narrow_to("1.4"),
            (ComponentKind::Container, false)
        );
    }

    #[test]
    fn a_version_is_only_offered_to_its_own_family() {
        let doc = SbomDoc {
            spec: Some(SpecOrigin::new("spdx", "SPDX-2.3")),
            ..Default::default()
        };
        assert_eq!(doc.version_within("spdx"), Some("SPDX-2.3"));
        // A CycloneDX writer must not adopt an SPDX version.
        assert_eq!(doc.version_within("cyclonedx"), None);
    }

    #[test]
    fn hash_algorithms_are_canonicalized_on_the_way_in() {
        // SPDX writes SHA256, CycloneDX requires SHA-256; without a single
        // spelling, SPDX -> CycloneDX emits a document that fails its schema.
        assert_eq!(Hash::canonical_algorithm("SHA256"), "SHA-256");
        assert_eq!(Hash::canonical_algorithm("SHA-256"), "SHA-256");
        assert_eq!(Hash::canonical_algorithm("sha1"), "SHA-1");
        assert_eq!(Hash::canonical_algorithm("BLAKE2b-256"), "BLAKE2b-256");
        assert_eq!(Hash::canonical_algorithm("MD5"), "MD5");
    }

    #[test]
    fn identity_prefers_the_purl() {
        let mut component = Component::new("lodash");
        component.version = Some("4.17.21".into());
        component.group = Some("@types".into());
        assert_eq!(component.identity(), "@types/lodash@4.17.21");

        component.purl = Some("pkg:npm/lodash@4.17.21".into());
        assert_eq!(component.identity(), "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn merge_matches_components_on_identity() {
        let make = |purl: &str| {
            let mut doc = SbomDoc::default();
            let mut component = Component::new("lodash");
            component.purl = Some(purl.into());
            doc.components.push(component);
            doc
        };

        let mut doc = make("pkg:npm/lodash@4.17.21");
        doc.merge(make("pkg:npm/lodash@4.17.21"));
        assert_eq!(doc.components.len(), 1, "the same package, listed twice");

        doc.merge(make("pkg:npm/lodash@4.17.20"));
        assert_eq!(
            doc.components.len(),
            2,
            "a different version is a different component"
        );
    }

    #[test]
    fn merge_unions_the_dependency_graph() {
        let mut doc = SbomDoc {
            dependencies: vec![Dependency {
                bom_ref: "a".into(),
                depends_on: vec!["b".into()],
            }],
            ..Default::default()
        };
        doc.merge(SbomDoc {
            dependencies: vec![Dependency {
                bom_ref: "a".into(),
                depends_on: vec!["b".into(), "c".into()],
            }],
            ..Default::default()
        });

        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].depends_on, ["b", "c"]);
    }
}
