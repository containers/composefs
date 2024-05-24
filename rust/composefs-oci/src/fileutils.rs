use std::io;
use std::path::Path;

use anyhow::Result;
use cap_std_ext::{
    cap_std::fs::{
        DirBuilder, DirBuilderExt as _, OpenOptions, OpenOptionsExt as _, Permissions,
        PermissionsExt as _,
    },
    cap_tempfile::TempFile,
};
use rustix::{
    fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    fs::openat,
};

/// The default permissions set for directories; we assume
/// nothing else should be accessing this content.  If you want
/// that, you can chmod() after, or use ACLs.
pub(crate) fn rwx_perms() -> Permissions {
    Permissions::from_mode(0o700)
}
/// The default permissions for regular files.  Ditto per above.
pub(crate) fn r_perms() -> Permissions {
    Permissions::from_mode(0o400)
}

pub(crate) fn default_dirbuilder() -> DirBuilder {
    let mut builder = DirBuilder::new();
    builder.mode(rwx_perms().mode());
    builder
}

/// For creating a file with the default permissions
pub(crate) fn default_file_create_options() -> OpenOptions {
    let mut r = OpenOptions::new();
    r.create(true);
    r.mode(r_perms().mode());
    r
}

/// Given a string, verify it is a single component of a path; it must
/// not contain `/`.
pub(crate) fn validate_single_path_component(s: &str) -> Result<()> {
    anyhow::ensure!(!s.contains('/'));
    Ok(())
}

pub(crate) fn parent_nonempty(p: &Path) -> Option<&Path> {
    p.parent().filter(|v| !v.as_os_str().is_empty())
}

// Just ensures that path is not absolute, so that it can be passed
// to cap-std APIs.  This makes no attempt
// to avoid directory escapes like `../` under the assumption
// that will be handled by a higher level function.
pub(crate) fn ensure_relative_path(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

/// Operates on a generic openat fd
pub(crate) fn ensure_dir(fd: BorrowedFd, p: &Path) -> io::Result<bool> {
    use rustix::fs::AtFlags;
    let mode = rwx_perms().mode();
    match rustix::fs::mkdirat(fd, p, rustix::fs::Mode::from_raw_mode(mode)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let st = rustix::fs::statat(fd, p, AtFlags::SYMLINK_NOFOLLOW)?;
            if !(st.st_mode & libc::S_IFDIR > 0) {
                // TODO use https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.NotADirectory
                // once it's stable.
                return Err(io::Error::new(io::ErrorKind::Other, "Found non-directory"));
            }
            Ok(false)
        }
        // If we got ENOENT, then loop again, but create the parents
        Err(e) => Err(e.into()),
    }
}

/// The cap-std default does not use RESOLVE_IN_ROOT; this does.
/// Additionally for good measure we use NO_MAGICLINKS and NO_XDEV.
/// We never expect to encounter a mounted /proc in our use cases nor
/// any other mountpoints at all really, but still.
pub(crate) fn openat_rooted(
    dirfd: BorrowedFd,
    path: impl AsRef<Path>,
) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{OFlags, ResolveFlags};
    rustix::fs::openat2(
        dirfd,
        path.as_ref(),
        OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::PATH,
        rustix::fs::Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )
}

/// Not all operations can be performed on an O_PATH directory; e.g.
/// fsetxattr() can't.
pub fn fsetxattr<Fd: AsFd>(
    fd: Fd,
    name: &str,
    value: &[u8],
    flags: rustix::fs::XattrFlags,
) -> rustix::io::Result<()> {
    let path = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    rustix::fs::setxattr(&path, name, value, flags)
}

/// Manual implementation of recursive dir walking using openat2
pub(crate) fn ensure_dir_recursive(fd: BorrowedFd, p: &Path, init: bool) -> io::Result<bool> {
    // Optimize the initial case by skipping the recursive calls;
    // we just call mkdirat() and no-op if we get EEXIST
    if !init {
        if let Some(parent) = parent_nonempty(p) {
            ensure_dir_recursive(fd, parent, false)?;
        }
    }
    match ensure_dir(fd, p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ensure_dir_recursive(fd, p, false),
        Err(e) => Err(e),
    }
}

/// Given a cap-std tmpfile, reopen its file in read-only mode.  This is
/// needed for fsverity support.
pub(crate) fn reopen_tmpfile_ro(tf: &mut TempFile) -> std::io::Result<()> {
    let procpath = format!("/proc/self/fd/{}", tf.as_file().as_fd().as_raw_fd());
    let tf_ro = cap_std_ext::cap_std::fs::File::open_ambient(
        procpath,
        cap_std_ext::cap_std::ambient_authority(),
    )?;
    let tf = tf.as_file_mut();
    *tf = tf_ro;
    Ok(())
}

// pub(crate) fn normalize_path(path: &Utf8Path) -> Result<Utf8PathBuf> {
//     let mut components = path.components().peekable();
//     let r = if !matches!(components.peek(), Some(camino::Utf8Component::RootDir)) {
//         [camino::Utf8Component::RootDir]
//             .into_iter()
//             .chain(components)
//             .collect()
//     } else {
//         components.collect()
//     };
//     Ok(r)
// }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_relpath() {
        let expected_foobar = "foo/bar";
        let cases = [("foo/bar", expected_foobar), ("/foo/bar", expected_foobar)];
        for (a, b) in cases {
            assert_eq!(ensure_relative_path(Path::new(a)), Path::new(b));
        }
        let idem = ["./foo/bar", "./foo", "./"];
        for case in idem {
            assert_eq!(ensure_relative_path(Path::new(case)), Path::new(case));
        }
    }
}
