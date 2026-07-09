mod common;

use std::fs::{self, File};
use std::io::BufReader;
use std::process::Command;

use assert_cmd::prelude::*;
use backhand::{FilesystemReader, XattrPrefix};
use tempfile::tempdir_in;
use test_log::test;

const BIG_VALUE_LEN: usize = 200;

/// Build a tiny SquashFS image with `mksquashfs -xattrs-add`, with every table's compression
/// disabled so the fixture is readable regardless of which single compressor feature is enabled
/// for this test run.
fn build_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("src");
    fs::create_dir_all(src.join("dir1")).unwrap();
    fs::write(src.join("file1.txt"), b"hello world\n").unwrap();
    fs::write(src.join("dir1/file2.txt"), b"nested\n").unwrap();

    let big_value = "A".repeat(BIG_VALUE_LEN);
    let out = dir.join("out.squashfs");

    let mut cmd = Command::new("mksquashfs");
    cmd.args([
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        "-xattrs-add",
        "user.foo=bar",
        "-xattrs-add",
        "security.baz=qux",
        "-xattrs-add",
        &format!("trusted.big={big_value}"),
        "-noI",
        "-noD",
        "-noF",
        "-noX",
        "-no-fragments",
        "-all-root",
        "-noappend",
    ]);
    cmd.assert().success();

    out
}

/// Reading a SquashFS image built with `mksquashfs -xattrs-add` should decode the same
/// user/security/trusted attributes that were written, including an out-of-line-eligible value
/// (`trusted.big`, larger than `XATTR_INLINE_MAX`).
#[test]
fn test_read_xattrs() {
    let tmp_dir = tempdir_in(".").unwrap();
    let image = build_fixture(tmp_dir.path());

    let file = BufReader::new(File::open(&image).unwrap());
    let filesystem = FilesystemReader::from_reader(file).unwrap();

    let big_value = "A".repeat(BIG_VALUE_LEN);
    let expected: Vec<(XattrPrefix, &str, Vec<u8>)> = vec![
        (XattrPrefix::User, "foo", b"bar".to_vec()),
        (XattrPrefix::Security, "baz", b"qux".to_vec()),
        (XattrPrefix::Trusted, "big", big_value.into_bytes()),
    ];

    let mut nodes_with_xattrs = 0;
    for node in filesystem.files() {
        if node.xattrs.is_empty() {
            continue;
        }
        nodes_with_xattrs += 1;

        assert_eq!(node.xattrs.len(), expected.len(), "node: {:?}", node.fullpath);
        for (prefix, name, value) in &expected {
            let found =
                node.xattrs.iter().find(|x| x.prefix == *prefix && x.name == *name).unwrap_or_else(
                    || panic!("missing xattr {}{} on {:?}", prefix.as_str(), name, node.fullpath),
                );
            assert_eq!(&found.value, value, "value mismatch for {}{}", prefix.as_str(), name);
        }
    }

    // both file1.txt and dir1/file2.txt were created under the xattr'd source tree
    assert!(
        nodes_with_xattrs >= 2,
        "expected at least 2 nodes with xattrs, got {nodes_with_xattrs}"
    );
}

/// Cross-check the `user.*` namespace (the only one extractable without root) against
/// `squashfs-tools` itself.
#[test]
fn test_read_xattrs_matches_squashfs_tools() {
    let tmp_dir = tempdir_in(".").unwrap();
    let image = build_fixture(tmp_dir.path());
    let extract_dir = tmp_dir.path().join("extracted");

    Command::new("unsquashfs")
        .args([
            "-d",
            extract_dir.to_str().unwrap(),
            "-xattrs-include",
            r"^user\.",
            image.to_str().unwrap(),
        ])
        .assert()
        .success();

    let getfattr = Command::new("getfattr")
        .args(["-d", "--absolute-names"])
        .arg(extract_dir.join("file1.txt"))
        .output()
        .unwrap();
    let getfattr_out = String::from_utf8(getfattr.stdout).unwrap();
    assert!(getfattr_out.contains(r#"user.foo="bar""#), "getfattr output: {getfattr_out}");

    let file = BufReader::new(File::open(&image).unwrap());
    let filesystem = FilesystemReader::from_reader(file).unwrap();
    let node = filesystem
        .files()
        .find(|n| n.fullpath.file_name().is_some_and(|n| n == "file1.txt"))
        .unwrap();
    let xattr =
        node.xattrs.iter().find(|x| x.prefix == XattrPrefix::User && x.name == "foo").unwrap();
    assert_eq!(xattr.value, b"bar");
}
