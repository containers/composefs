//! # Creating composefs images
//!
//! This code wraps `mkcomposefs`, supporting synthesizing a composefs
//! from dump file entries.

use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::sync::mpsc;

use anyhow::{Context, Result};

/// Configuration for `mkcomposefs`
#[derive(Debug, Default)]
pub struct Config {
    digest_store: Option<String>,
    min_version: Option<u32>,
    max_version: Option<u32>,
}

impl Config {
    fn to_args(&self) -> impl Iterator<Item = String> {
        self.digest_store
            .as_deref()
            .map(|v| format!("--digest-store={v}"))
            .into_iter()
            .chain(self.min_version.map(|v| format!("--min-version={v}")))
            .chain(self.max_version.map(|v| format!("--max-version={v}")))
    }
}

/// Prepare a child process invocation of `mkcomposefs`.  It will accept
/// serialized dumpfile lines on stdin, and write output to stdout.
fn new_mkcomposefs_command(config: Config, output: File) -> Result<Command> {
    let mut proc = Command::new("mkcomposefs");
    proc.args(config.to_args())
        .args(["--from-file", "-", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(output));
    Ok(proc)
}

/// Given the provided configuration and dumpfile entries, write a composefs metadata file to `output`.
pub fn mkcomposefs(
    config: Config,
    entries: mpsc::Receiver<super::dumpfile::Entry<'_>>,
    output: File,
) -> Result<()> {
    let mut cmd = new_mkcomposefs_command(config, output)?;
    let mut proc = cmd.spawn().context("Spawning mkcomposefs")?;
    // SAFETY: we set up stdin
    let mut child_stdin = std::io::BufWriter::new(proc.stdin.take().unwrap());
    std::thread::scope(|s| {
        // Spawn a helper thread which handles writing to the child stdin, while the main
        // thread handles reading from stderr (if any) and otherwise just being blocked in wait().
        // The composefs subprocess itself writes to the output file.
        let writer = s.spawn(move || -> anyhow::Result<()> {
            for entry in entries {
                writeln!(child_stdin, "{entry}")?;
            }
            // Flush and close child's stdin
            drop(child_stdin.into_inner()?);
            Ok(())
        });
        let r = proc.wait_with_output()?;
        if !r.status.success() {
            let stderr = String::from_utf8_lossy(&r.stderr);
            let stderr = stderr.trim();
            anyhow::bail!("mkcomposefs failed: {}: {stderr}", r.status)
        }
        // SAFETY: We shouldn't fail to join the thread
        writer.join().unwrap()?;
        anyhow::Ok(())
    })
}

#[test]
fn test_mkcomposefs() -> Result<()> {
    use super::dumpfile::Entry;
    use std::fmt::Write as _;
    let td = tempfile::tempdir()?;
    let td = td.path();
    let outpath = &td.join("out");
    let o = File::create(outpath)?;
    let (send, recv) = mpsc::sync_channel(5);
    const CONTENT: &str = include_str!("../../../tests/assets/special.dump");
    std::thread::scope(|s| {
        let producer = s.spawn(move || {
            for line in CONTENT.lines() {
                if send.send(Entry::parse(line)?).is_err() {
                    break;
                }
            }
            anyhow::Ok(())
        });
        mkcomposefs(Config::default(), recv, o)?;
        producer.join().unwrap()?;
        anyhow::Ok(())
    })?;
    let mut reparsed_content = String::new();
    let o = File::open(outpath)?;
    super::dump(o, |entry| {
        writeln!(reparsed_content, "{entry}").map_err(anyhow::Error::from)
    })
    .unwrap();
    let mut reparsed_content = reparsed_content.lines().fuse();
    for line in CONTENT.lines() {
        assert_eq!(line, reparsed_content.next().unwrap());
    }
    assert!(reparsed_content.next().is_none());
    Ok(())
}
