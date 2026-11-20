use std::{fs, os::unix::fs::MetadataExt};

use anyhow::{Context, Result};

pub fn current_inode() -> Result<u32> {
    u32::try_from(fs::metadata("/proc/thread-self/ns/net")?.ino())
        .context("network namespace inode exceeds u32")
}
