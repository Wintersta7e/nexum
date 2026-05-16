//! Pinned bge-m3 ONNX file manifest. Files match the BAAI/bge-m3
//! `SentenceTransformers` ONNX export on Hugging Face. Hashes verified by
//! direct download into the model dir; bumping is a deliberate
//! release-time decision.

/// One entry in the bge-m3 manifest: file name (joined onto the model
/// base URL at download time), expected size in bytes, and the SHA256
/// hash as a lower-case hex string.
#[derive(Debug, Clone, Copy)]
pub struct ManifestEntry {
    name: &'static str,
    size: u64,
    sha256: &'static str,
}

impl ManifestEntry {
    /// Construct a manifest entry. The `sha256` argument must be a 64-char
    /// lower-case hex string; mismatches panic at compile time so a
    /// paste-the-wrong-prefix typo can never reach a committed manifest.
    ///
    /// # Panics
    ///
    /// Panics if `sha256` is not exactly 64 lower-case hex characters. Because
    /// the function is `const`, the panic is evaluated at compile time when the
    /// argument is a string literal, so a malformed hash fails the build rather
    /// than the user's install.
    #[must_use]
    pub const fn new(name: &'static str, size: u64, sha256: &'static str) -> Self {
        assert!(sha256.len() == 64, "sha256 must be 64 hex chars");
        let bytes = sha256.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            let lower = matches!(b, b'0'..=b'9' | b'a'..=b'f');
            assert!(lower, "sha256 must be lower-case hex");
            i += 1;
        }
        Self { name, size, sha256 }
    }

    /// The file name, used as the last path component of the download URL
    /// and the local destination filename.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Expected size of this file in bytes, used as a progress-bar hint
    /// when the server omits a `Content-Length` header.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// SHA256 of the file as a 64-char lower-case hex string. Verified
    /// after every download; a mismatch triggers one retry then a hard
    /// failure.
    #[must_use]
    pub const fn sha256(&self) -> &'static str {
        self.sha256
    }
}

/// The four bge-m3 ONNX export files. ORT's external-data format puts
/// the weights (`model.onnx_data` ~2.1 GB) alongside the graph
/// (`model.onnx` 725 KB) plus a tiny `Constant_7_attr__value` shard;
/// the tokenizer ships in the same dir.
pub const BGE_M3_FILES: &[ManifestEntry; 4] = &[
    ManifestEntry::new(
        "model.onnx",
        724_923,
        "f84251230831afb359ab26d9fd37d5936d4d9bb5d1d5410e66442f630f24435b",
    ),
    ManifestEntry::new(
        "model.onnx_data",
        2_266_820_608,
        "1eebfb28493f67bba03ce0ef64bfdc7fc5a3bd9d7493f818bb1d78cd798416b4",
    ),
    ManifestEntry::new(
        "Constant_7_attr__value",
        65_552,
        "cdf16f72c5d07b36484056e601ed9687f78477e5d85cee85a34f2406b7fb5906",
    ),
    ManifestEntry::new(
        "tokenizer.json",
        17_082_821,
        "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    ),
];

/// Total bytes the bge-m3 install downloads. Useful for the install
/// command's progress reporter.
#[must_use]
pub const fn bge_m3_total_bytes() -> u64 {
    let mut total = 0u64;
    let mut i = 0;
    while i < BGE_M3_FILES.len() {
        total += BGE_M3_FILES[i].size();
        i += 1;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_lowercase_64_hex() {
        let entry = ManifestEntry::new(
            "ok.bin",
            42,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(entry.name(), "ok.bin");
        assert_eq!(entry.size(), 42);
        assert_eq!(entry.sha256().len(), 64);
    }

    #[test]
    fn manifest_has_exactly_four_entries() {
        assert_eq!(BGE_M3_FILES.len(), 4);
    }

    #[test]
    fn manifest_total_matches_sum_of_entries() {
        // 2.13 GiB ≈ 2_284_693_904 bytes; the sum of the four entry sizes
        // pinned above (graph + weights + tiny shard + tokenizer).
        assert_eq!(bge_m3_total_bytes(), 2_284_693_904);
    }

    #[test]
    fn sha256_hashes_are_64_hex_chars() {
        for entry in BGE_M3_FILES {
            assert_eq!(
                entry.sha256().len(),
                64,
                "{}: not 64 hex chars",
                entry.name()
            );
            assert!(
                entry
                    .sha256()
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{}: not lower-case hex",
                entry.name(),
            );
        }
    }

    #[test]
    fn entries_named_for_external_data_format() {
        // model.onnx (graph) + model.onnx_data (weights) + the tiny
        // constant shard + the tokenizer. Missing any one would break
        // the install flow.
        let names: Vec<&str> = BGE_M3_FILES.iter().map(ManifestEntry::name).collect();
        assert!(names.contains(&"model.onnx"));
        assert!(names.contains(&"model.onnx_data"));
        assert!(names.contains(&"Constant_7_attr__value"));
        assert!(names.contains(&"tokenizer.json"));
    }
}
