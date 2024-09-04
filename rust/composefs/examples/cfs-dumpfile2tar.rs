use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow as error;
use anyhow::Context;
use anyhow::Result;
use composefs::dumpfile::Entry;
use composefs::dumpfile::Item;

const PAX_SCHILY_XATTR: &[u8] = b"SCHILY.xattr.";

/// Convert an input path to relative as it's what tar wants.
fn make_relative(p: &Path) -> &Path {
    let p = p.strip_prefix("/").unwrap_or(p);
    // Special case `/` -> `.`
    // All other paths just have the leading `/` removed.
    if p.as_os_str().is_empty() {
        Path::new(".")
    } else {
        p
    }
}

fn entry_to_tar<W: Write>(e: &Entry, w: &mut tar::Builder<W>) -> Result<()> {
    let path = make_relative(&e.path);
    let mut h = tar::Header::new_ustar();
    let fmt = e.mode & libc::S_IFMT;
    h.set_mode(e.mode);
    h.set_uid(e.uid.into());
    h.set_gid(e.gid.into());
    // Discard nanos currently
    h.set_mtime(e.mtime.sec);
    match e.xattrs.as_slice() {
        [] => {}
        xattrs => {
            // Match "--pax-option=exthdr.name=%d/PaxHeaders/%f" as recommended by
            // https://reproducible-builds.org/docs/archives/
            let dirname = path.parent().unwrap_or(Path::new("/"));
            let name = path.file_name().unwrap_or(path.as_os_str());
            let mut header_name = PathBuf::from(dirname);
            header_name.push("PaxHeaders");
            header_name.push(name);
            let mut pax_header = tar::Header::new_ustar();
            let mut pax_data = Vec::new();
            for xattr in xattrs {
                let key = xattr.key.as_bytes();
                let value = &xattr.value;
                let data_len = PAX_SCHILY_XATTR.len() + key.len() + value.len() + 3;
                // Calculate the total length, including the length of the length field
                let mut len_len = 1;
                while data_len + len_len >= 10usize.pow(len_len.try_into().unwrap()) {
                    len_len += 1;
                }
                write!(pax_data, "{} ", data_len + len_len)?;
                pax_data.write_all(PAX_SCHILY_XATTR)?;
                pax_data.write_all(key)?;
                pax_data.write_all(b"=")?;
                pax_data.write_all(value)?;
                pax_data.write_all(b"\n")?;
            }
            assert!(!pax_data.is_empty());
            pax_header.set_path(header_name)?;
            pax_header.set_size(pax_data.len().try_into().unwrap());
            pax_header.set_entry_type(tar::EntryType::XHeader);
            pax_header.set_cksum();
            w.append(&pax_header, &*pax_data)?;
        }
    }
    match &e.item {
        Item::Regular {
            inline_content,
            size,
            ..
        } => {
            h.set_entry_type(tar::EntryType::Regular);
            if let Some(inline_content) = inline_content.as_deref() {
                h.set_size(inline_content.len().try_into()?);
                w.append_data(&mut h, path, inline_content)?;
            } else if *size == 0 {
                h.set_size(0);
                w.append_data(&mut h, path, std::io::empty())?;
            } else {
                anyhow::bail!("Cannot convert non-inline/non-zero-size file to tar");
            }
        }
        Item::Device { rdev, .. } => {
            let rdev: u64 = (*rdev).into();
            if fmt == libc::S_IFBLK {
                h.set_entry_type(tar::EntryType::Block);
            } else if fmt == libc::S_IFCHR {
                h.set_entry_type(tar::EntryType::Char)
            } else {
                panic!("Unhandled mode for device entry: {e}");
            }
            let major = ((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0x0000_0fff);
            let minor = ((rdev >> 12) & 0xffff_ff00) | ((rdev) & 0x0000_00ff);
            h.set_device_major(major as u32)?;
            h.set_device_minor(minor as u32)?;
            w.append_data(&mut h, path, std::io::empty())?;
        }
        Item::Symlink { target, .. } => {
            h.set_entry_type(tar::EntryType::Symlink);
            w.append_link(&mut h, path, target)?;
        }
        Item::Hardlink { target } => {
            h.set_entry_type(tar::EntryType::Link);
            w.append_link(&mut h, path, target)?;
        }
        Item::Fifo { .. } => {
            h.set_entry_type(tar::EntryType::Fifo);
            w.append_data(&mut h, path, std::io::empty())?;
        }
        Item::Directory { .. } => {
            h.set_entry_type(tar::EntryType::Directory);
            w.append_data(&mut h, path, std::io::empty())?;
        }
    }

    Ok(())
}

fn dumpfile_to_tar(src: impl Read, dst: impl Write) -> Result<()> {
    let src = BufReader::new(src);
    let dst = BufWriter::new(dst);
    let mut dst = tar::Builder::new(dst);
    for line in src.lines() {
        let line = line?;
        let entry = Entry::parse(&line)?;
        entry_to_tar(&entry, &mut dst).with_context(|| format!("Processing entry: {entry}"))?;
    }
    dst.into_inner()?.into_inner().map_err(|e| e.into_error())?;
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let src = args.get(1).ok_or_else(|| error!("Missing src"))?;
    let dst = args.get(2).ok_or_else(|| error!("Missing dest"))?;

    let src = File::open(src)
        .map(BufReader::new)
        .with_context(|| format!("Opening {src}"))?;
    let dst = File::create(dst)
        .map(BufWriter::new)
        .with_context(|| format!("Opening {dst}"))?;

    dumpfile_to_tar(src, dst)
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(e) = run(&args) {
        eprintln!("{:#}", e);
    }
}
