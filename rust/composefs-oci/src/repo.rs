use std::borrow::Cow;
use std::cell::OnceCell;
use std::fs::File;
use std::io::{self, BufRead, Seek, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{DirBuilder, DirBuilderExt, PermissionsExt};
use cap_std_ext::cap_tempfile::{TempDir, TempFile};
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::dumpfile::{self, Entry};
use composefs::fsverity::Digest;
use composefs::mkcomposefs::{self, mkcomposefs};
use fn_error_context::context;
use rustix::fd::{AsRawFd, BorrowedFd};
use rustix::fs::{openat, AtFlags};
use serde::{Deserialize, Serialize};

use crate::fileutils;

const REPOMETA: &str = "meta.json";
const OBJECTS: &str = "objects";
const LAYERS: &str = "layers";
const IMAGES: &str = "images";
const TMP: &str = "tmp";
const LAYER_CFS: &str = "layer.cfs";
const BOOTID_XATTR: &str = "user.composefs-oci.bootid";
/// A container including content here is basically trying to
/// do something malicious, so we'll just reject it.
const API_FILESYSTEMS: &[&str] = &["proc", "sys", "dev"];

/// The extended attribute we attach with the target metadata
const CFS_ENTRY_META_XATTR: &str = "user.cfs.entry.meta";
/// This records the virtual number of links (as opposed to
/// the physical, because we may share multiple regular files
/// by hardlinking into the object store).
const CFS_ENTRY_META_NLINK: &str = "user.cfs.entry.nlink";

///
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RepoMetadata {
    // Must currently be 0.1
    version: String,
    // Set to true if and only if we detected the filesystem supports fs-verity
    // and all objects should have been initialized that way.
    verity: bool,
}

/// This metadata is serialized underneath the `CFS_ENTRY_META_XATTR`
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OverrideMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: Option<u32>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

fn get_bootid() -> &'static str {
    static BOOTID: OnceLock<String> = OnceLock::new();
    let bootid =
        BOOTID.get_or_init(|| std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap());
    bootid.as_str()
}

fn create_entry(h: tar::Header) -> Result<Entry<'static>> {
    // let size = h.size()?;
    // let path = &*h.path()?;
    // let path = Utf8Path::from_path(path)
    //     .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF8 path: {path:?}"))?;
    // let path: Cow<std::path::Path> = Cow::Owned(PathBuf::from("."));
    // let mtime = dumpfile::Mtime {
    //     sec: h.mtime()?,
    //     nsec: 0,
    // };
    // // The data below are stubs, we'll fix it up after
    // let nlink = 1;
    // let inline_content = None;
    // let fsverity_digest = None;

    // use dumpfile::Item;
    // let item = match h.entry_type() {
    //     tar::EntryType::Regular => {}
    //     tar::EntryType::Link => todo!(),
    //     tar::EntryType::Symlink => todo!(),
    //     tar::EntryType::Char => todo!(),
    //     tar::EntryType::Block => todo!(),
    //     tar::EntryType::Directory => todo!(),
    //     tar::EntryType::Fifo => todo!(),
    //     tar::EntryType::Continuous => todo!(),
    //     tar::EntryType::GNULongName => todo!(),
    //     tar::EntryType::GNULongLink => todo!(),
    //     tar::EntryType::GNUSparse => todo!(),
    //     tar::EntryType::XGlobalHeader => todo!(),
    //     tar::EntryType::XHeader => todo!(),
    //     _ => todo!(),
    // };

    // let entry = Entry {
    //     path,
    //     uid: h.uid().context("uid")?.try_into()?,
    //     gid: h.gid().context("gid")?.try_into()?,
    //     mode: h.mode().context("mode")?,
    //     mtime,
    //     item: todo!(),
    //     xattrs: todo!(),
    // };

    todo!()
}

// fn reject_api_filesystem_path(p: &Path) -> Result<()> {
//     for part in API_FILESYSTEMS {
//         if let Ok(r) = p.strip_prefix(part) {

//         }
//     }
//     Ok(())
// }

#[context("Initializing object dir")]
fn init_object_dir(objects: &Dir) -> Result<()> {
    for prefix in 0..=0xFFu8 {
        let path = format!("{:02x}", prefix);
        objects.ensure_dir_with(path, &fileutils::default_dirbuilder())?;
    }
    Ok(())
}

#[context("Checking fsverity")]
fn test_fsverity_in(d: &Dir) -> Result<bool> {
    let mut tf = TempFile::new(&d)?;
    tf.write_all(b"test")?;
    fileutils::reopen_tmpfile_ro(&mut tf)?;
    Ok(composefs::fsverity::fsverity_enable(tf.as_file().as_fd()).is_ok())
}

struct ImportContext {
    has_verity: bool,
    /// Reference to global objects
    global_objects: Dir,
    // Temporary directory for layer import;
    // This contains:
    //  - objects/   Regular file content (not fsync'd yet!)
    //  - root/      The layer rootfs
    workdir: TempDir,
    // Handle for objects/ above
    tmp_objects: Dir,
    // This fd is using openat2 for more complete sandboxing, unlike default
    // cap-std which doesn't use RESOLVE_BENEATH which we need to handle absolute
    // symlinks.
    layer_root: rustix::fd::OwnedFd,
}

impl ImportContext {
    fn import(&self, src: File) -> Result<ImportLayerStats> {
        let mut stats = ImportLayerStats::default();
        let src = std::io::BufReader::new(src);
        let mut archive = tar::Archive::new(src);

        for entry in archive.entries()? {
            let entry = entry?;

            let etype = entry.header().entry_type();
            // Make a copy because it may refer into the header, but we need it
            // after we process the entry too.
            let path = entry.header().path()?;
            if let Some(parent) = fileutils::parent_nonempty(&path) {
                fileutils::ensure_dir_recursive(self.layer_root.as_fd(), parent, true)
                    .with_context(|| format!("Creating parents for {path:?}"))?;
            };

            match etype {
                tar::EntryType::Regular => {
                    // Copy as we need to refer to it after processing the entry
                    let path = path.into_owned();
                    self.unpack_regfile(entry, &path, &mut stats)?;
                }
                tar::EntryType::Link => {
                    let target = entry
                        .link_name()
                        .context("linkname")?
                        .ok_or_else(|| anyhow::anyhow!("Missing hardlink target"))?;
                    rustix::fs::linkat(
                        self.layer_root.as_fd(),
                        &*path,
                        self.layer_root.as_fd(),
                        &*target,
                        AtFlags::empty(),
                    )
                    .with_context(|| format!("hardlinking {path:?} to {target:?}"))?;
                    stats.meta_count += 1;
                }
                tar::EntryType::Symlink => {
                    let target = entry
                        .link_name()
                        .context("linkname")?
                        .ok_or_else(|| anyhow::anyhow!("Missing hardlink target"))?;
                    rustix::fs::symlinkat(&*target, self.layer_root.as_fd(), &*path)
                        .with_context(|| format!("symlinking {path:?} to {target:?}"))?;
                    stats.meta_count += 1;
                }
                tar::EntryType::Char | tar::EntryType::Block => {
                    todo!()
                }
                tar::EntryType::Directory => {
                    fileutils::ensure_dir(self.layer_root.as_fd(), &path)?;
                }
                tar::EntryType::Fifo => todo!(),
                o => anyhow::bail!("Unhandled entry type: {o:?}"),
            }
        }
        Ok(stats)
    }

    async fn commit_objects_in(&self, prefix: &str) -> Result<()> {
        let src = Arc::new(self.tmp_objects.open_dir(prefix).context("tmp objects")?);
        let dest = Arc::new(
            self.global_objects
                .open_dir(prefix)
                .context("global objects")?,
        );
        let mut tasks = tokio::task::JoinSet::new();
        for ent in src.entries()? {
            let ent = ent?;
            let name = ent.file_name();
            let src = Arc::clone(&src);
            let dest = Arc::clone(&dest);
            tasks.spawn_blocking(move || -> Result<()> {
                let f = src.open(&name)?;
                f.sync_all().context("fsync")?;
                match src.rename(&name, &dest, &name) {
                    Ok(()) => Ok(()),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::AlreadyExists) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            });
        }
        while let Some(r) = tasks.join_next().await {
            r.context("join")?.context("Renaming into global")?;
        }
        Ok(())
    }

    #[context("Committing objects")]
    async fn commit_tmpobjects(&self) -> Result<()> {
        for d in self.tmp_objects.entries()? {
            let d = d?;
            if !d.file_type()?.is_dir() {
                continue;
            }
            let name = d.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            self.commit_objects_in(name)
                .await
                .with_context(|| name.to_owned())?;
        }
        Ok(())
    }

    #[context("Unpacking regfile")]
    fn unpack_regfile<E: std::io::Read>(
        &self,
        mut entry: tar::Entry<E>,
        path: &Path,
        stats: &mut ImportLayerStats,
    ) -> Result<()> {
        use rustix::fs::AtFlags;
        // First, spool the file content to a temporary file
        let mut tmpfile = TempFile::new(&self.tmp_objects).context("Creating tmpfile")?;
        let wrote_size = std::io::copy(&mut entry, &mut tmpfile)
            .with_context(|| format!("Copying tar entry {:?} to tmpfile", path))?;
        tmpfile.seek(std::io::SeekFrom::Start(0))?;

        // Load metadata
        let header = entry.header();
        let size = header.size().context("header size")?;
        // This should always be true, but just in case
        anyhow::ensure!(size == wrote_size);

        // Compute its composefs digest.  This can be an expensive operation,
        // so in the future it'd be nice to do this is a helper thread.  However
        // doing so would significantly complicate the flow.
        if self.has_verity {
            fileutils::reopen_tmpfile_ro(&mut tmpfile).context("Reopening tmpfile")?;
            composefs::fsverity::fsverity_enable(tmpfile.as_file().as_fd())
                .context("Failed to enable fsverity")?;
        };
        let mut digest = Digest::new();
        composefs::fsverity::fsverity_digest_from_fd(tmpfile.as_file().as_fd(), &mut digest)
            .context("Computing fsverity digest")?;
        let mut buf = hex::encode(digest.get());
        buf.insert(2, '/');
        let exists_globally = self.global_objects.try_exists(&buf)?;
        let exists_locally = !exists_globally && self.tmp_objects.try_exists(&buf)?;
        if exists_globally {
            stats.extant_objects_count += 1;
            stats.extant_objects_size += size;
            rustix::fs::linkat(
                self.tmp_objects.as_fd(),
                &buf,
                self.layer_root.as_fd(),
                path,
                AtFlags::empty(),
            )
            .with_context(|| format!("Linking extant object {buf} to {path:?}"))?;
        } else {
            if !exists_locally {
                tmpfile.replace(&buf).context("tmpfile replace")?;
                stats.imported_objects_count += 1;
                stats.imported_objects_size += size;
            }
            rustix::fs::linkat(
                self.tmp_objects.as_fd(),
                &buf,
                self.layer_root.as_fd(),
                path,
                AtFlags::empty(),
            )
            .with_context(|| format!("Linking tmp object {buf} to {path:?}"))?;
        }

        Ok(())
    }
}

pub struct Repo {
    fd: Dir,
    bootid: &'static str,
    meta: RepoMetadata,
}

impl Repo {
    pub fn init(fd: Dir, require_verity: bool) -> Result<Self> {
        let supports_verity = test_fsverity_in(&fd)?;
        if require_verity && !supports_verity {
            anyhow::bail!("Requested fsverity, but target does not support it");
        }
        let meta = RepoMetadata {
            version: String::from("0.5"),
            verity: supports_verity,
        };
        if !fd.try_exists(REPOMETA)? {
            fd.atomic_replace_with(REPOMETA, |w| {
                serde_json::to_writer(w, &meta).map_err(anyhow::Error::msg)
            })?;
        }
        for d in [OBJECTS, LAYERS, IMAGES, TMP] {
            fd.ensure_dir_with(d, &fileutils::default_dirbuilder())
                .context(d)?;
        }
        let objects = fd.open_dir(OBJECTS)?;
        init_object_dir(&objects)?;
        Self::open(fd)
    }

    #[context("Opening composefs-oci repo")]
    pub fn open(fd: Dir) -> Result<Self> {
        let bootid = get_bootid();
        let meta = serde_json::from_reader(
            fd.open(REPOMETA)
                .map(std::io::BufReader::new)
                .context(REPOMETA)?,
        )?;
        Ok(Self { fd, bootid, meta })
    }

    pub fn has_verity(&self) -> bool {
        self.meta.verity
    }

    pub fn has_layer(&self, diffid: &str) -> Result<bool> {
        let layer_path = &format!("{LAYERS}/{diffid}");
        self.fd.try_exists(layer_path).map_err(Into::into)
    }

    pub async fn import_layer(&self, src: File, diffid: &str) -> Result<ImportLayerStats> {
        fileutils::validate_single_path_component(diffid).context("validating diffid")?;
        let layer_path = &format!("{LAYERS}/{diffid}");
        // If we've already fetched the layer, then assume the caller is forcing a re-import
        // to e.g. repair missing files.
        if self.fd.try_exists(layer_path)? {
            self.fd
                .remove_dir_all(layer_path)
                .context("removing extant layerdir")?;
        }
        let global_tmp = &self.fd.open_dir(TMP).context(TMP)?;
        let global_objects = self.fd.open_dir(OBJECTS).context(OBJECTS)?;
        let (workdir, tmp_objects) = {
            let d = TempDir::new_in(global_tmp)?;
            fileutils::fsetxattr(
                d.as_fd(),
                BOOTID_XATTR,
                self.bootid.as_bytes(),
                rustix::fs::XattrFlags::empty(),
            )
            .context("setting bootid xattr")?;
            d.create_dir("root")?;
            d.create_dir(OBJECTS)?;
            let objects = d.open_dir(OBJECTS)?;
            init_object_dir(&objects)?;
            (d, objects)
        };
        let layer_root = fileutils::openat_rooted(workdir.as_fd(), "root")
            .context("Opening sandboxed layer dir")?;

        let has_verity = self.has_verity();
        let (ctx, stats) = tokio::task::spawn_blocking(move || {
            let mut ctx = ImportContext {
                has_verity,
                global_objects,
                workdir,
                tmp_objects,
                layer_root,
            };
            let stats = ctx.import(src)?;
            anyhow::Ok((ctx, stats))
        })
        .await??;
        ctx.commit_tmpobjects().await?;
        Ok(stats)
    }
}

#[derive(Debug, Default)]
pub struct ImportLayerStats {
    /// Existing regular file count
    extant_objects_count: usize,
    /// Existing regular file size
    extant_objects_size: u64,

    /// Imported regular file count
    imported_objects_count: usize,
    /// Imported regular file size
    imported_objects_size: u64,

    /// Imported metadata
    meta_count: u64,
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, BufWriter},
        process::Command,
    };

    use super::*;

    fn new_memfd(buf: &[u8]) -> Result<File> {
        use rustix::fs::MemfdFlags;
        let f = rustix::fs::memfd_create("test memfd", MemfdFlags::CLOEXEC)?;
        let f = File::from(f);
        let mut bufw = std::io::BufWriter::new(f);
        std::io::copy(&mut std::io::Cursor::new(buf), &mut bufw)?;
        bufw.into_inner().map_err(Into::into)
    }

    #[tokio::test]
    async fn test_repo() -> Result<()> {
        let td = TempDir::new(cap_std::ambient_authority())?;
        let td = &*td;

        td.create_dir("repo")?;
        let repo = Repo::init(td.open_dir("repo")?, false).unwrap();
        eprintln!("verity={}", repo.has_verity());

        const EMPTY_DIFFID: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(!repo.has_layer(EMPTY_DIFFID).unwrap());

        // A no-op import
        let r = repo
            .import_layer(new_memfd(b"")?, EMPTY_DIFFID)
            .await
            .unwrap();
        assert_eq!(r.extant_objects_count, 0);
        assert_eq!(r.imported_objects_count, 0);
        assert_eq!(r.imported_objects_size, 0);

        // Serialize our own source code

        let testtar = td.create("test.tar").map(BufWriter::new)?;
        let mut testtar = tar::Builder::new(testtar);
        testtar.follow_symlinks(false);
        testtar
            .append_dir_all("./", "../../tests")
            .context("creating tar")?;
        drop(testtar.into_inner()?.into_inner()?);
        let digest_o = Command::new("sha256sum")
            .stdin(td.open("test.tar")?)
            .stdout(std::process::Stdio::piped())
            .output()?;
        assert!(digest_o.status.success());
        let digest = String::from_utf8(digest_o.stdout).unwrap();
        let digest = digest.split_ascii_whitespace().next().unwrap().trim();
        let testtar = td.open("test.tar")?;

        repo.import_layer(testtar.into_std(), digest).await.unwrap();

        Ok(())
    }
}
