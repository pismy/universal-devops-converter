//! FNV-1a 128-bit, used to synthesize stable fingerprints for formats that
//! require one (Code Climate / GitLab Code Quality) from formats that do not
//! carry one (Checkstyle, SARIF without `partialFingerprints`).
//!
//! Non-cryptographic by design: the requirement is stability across runs so a
//! platform can tell "same issue" from "new issue", not collision resistance.

const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

/// 32 lowercase hex characters, MD5-shaped so it drops into fields that expect
/// a digest-looking string.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut hash = OFFSET;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            // Separator prevents ("ab","c") and ("a","bc") colliding.
            hash = (hash ^ 0x1f).wrapping_mul(PRIME);
        }
        for byte in part.as_bytes() {
            hash = (hash ^ u128::from(*byte)).wrapping_mul(PRIME);
        }
    }
    format!("{hash:032x}")
}

#[cfg(test)]
mod tests {
    use super::fingerprint;

    #[test]
    fn is_stable_and_hex() {
        let a = fingerprint(&["src/a.rs", "no-unused", "12"]);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, fingerprint(&["src/a.rs", "no-unused", "12"]));
    }

    #[test]
    fn separator_disambiguates_parts() {
        assert_ne!(fingerprint(&["ab", "c"]), fingerprint(&["a", "bc"]));
    }
}
