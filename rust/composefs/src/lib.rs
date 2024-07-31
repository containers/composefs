//! # Rust composefs library
//!
//! This crate builds on top of the core composefs tooling; it currently requires
//! both the `libcomposefs` C library as well as the external executables
//! `mkcomposefs` and `composefs-info`.
//!
//! The core functionality exposed at the moment is just support for creating
//! and parsing composefs "superblock" entries.

// See https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::{Context, Result};
use dumpfile::Entry;

pub mod dumpfile;
pub mod mkcomposefs;

pub mod fsverity;

/// Parse a composefs superblock.  The provided callback will be invoked
/// for each entry in the target image, containing exactly one parsed entry.
///
/// This function depends on an external `composefs-info` binary currently.
pub fn dump<F>(f: File, mut callback: F) -> Result<()>
where
    F: FnMut(&'_ Entry) -> Result<()>,
{
    let mut cmd = std::process::Command::new("composefs-info");
    cmd.args(["dump", "/proc/self/fd/0"])
        .stdin(std::process::Stdio::from(f))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut proc = cmd.spawn().context("spawning composefs-info dump")?;
    // SAFETY: We provided a pipe
    let child_stdout = BufReader::new(proc.stdout.take().unwrap());
    std::thread::scope(|s| {
        let reader = s.spawn(move || -> anyhow::Result<()> {
            let r = proc.wait_with_output()?;
            if !r.status.success() {
                let stderr = String::from_utf8_lossy(&r.stderr);
                let stderr = stderr.trim();
                anyhow::bail!("composefs-info dump failed: {}: {stderr}", r.status)
            }
            Ok(())
        });
        for line in child_stdout.lines() {
            let line = line?;
            // FIXME: try removing filter_special
            let entry = Entry::parse(&line)?.filter_special();
            callback(&entry)?;
        }
        // SAFETY: We shouldn't fail to join the thread
        reader
            .join()
            .unwrap()
            .context("Processing composefs-info dump")?;
        anyhow::Ok(())
    })
}
