// Shared test utilities for nexum-core integration tests. Each test gets its own
// `NexumTestHome` (isolated temp dir, auto-cleaned on drop). Build a Paths value
// from it with `home.paths()` and pass that into the code under test.

use nexum_core::paths::Paths;
use std::path::Path;
use tempfile::TempDir;

pub struct NexumTestHome {
    tmp: TempDir,
}

impl NexumTestHome {
    pub fn new() -> std::io::Result<Self> {
        let tmp = tempfile::Builder::new()
            .prefix("nexum-test-home-")
            .tempdir()?;
        Ok(Self { tmp })
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    pub fn paths(&self) -> Paths {
        Paths::with_home(self.path().to_owned())
    }
}
