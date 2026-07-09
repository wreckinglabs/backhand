//! Extended attribute (xattr) support
//!
//! The on-disk xattr table has two regions:
//! - an id table (pointed to by [`crate::v4::squashfs::SuperBlock::xattr_table`]), one
//!   [`XattrId`] per inode that has xattrs, itself preceded by an [`XattrIdTable`] header
//! - a key/value metadata region (pointed to by [`XattrIdTable::xattr_table_start`]) containing
//!   the actual [`XattrEntry`]/value pairs referenced by each [`XattrId`]

use deku::prelude::*;
use solana_nohash_hasher::IntMap;

use crate::error::BackhandError;

/// Low byte of [`XattrEntry::xattr_type`]: which namespace this attribute belongs to.
const XATTR_PREFIX_MASK: u16 = 0x00ff;
/// Bit of [`XattrEntry::xattr_type`] indicating the value is stored out-of-line: the entry's
/// [`XattrValue`] holds a reference to the real value elsewhere, rather than inline bytes.
pub(crate) const XATTR_VALUE_OOL: u16 = 0x0100;

/// Namespace prefix of an extended attribute. SquashFS only supports these three (see
/// `prefix_table` in squashfs-tools' `read_xattrs.c`; POSIX ACLs and other `system.*` xattrs
/// are not representable in the on-disk xattr table).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum XattrPrefix {
    User,
    Trusted,
    Security,
}

impl XattrPrefix {
    /// On-disk prefix string, including the trailing `.`
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user.",
            Self::Trusted => "trusted.",
            Self::Security => "security.",
        }
    }
}

impl TryFrom<u16> for XattrPrefix {
    type Error = BackhandError;

    fn try_from(xattr_type: u16) -> Result<Self, Self::Error> {
        match xattr_type & XATTR_PREFIX_MASK {
            0 => Ok(Self::User),
            1 => Ok(Self::Trusted),
            2 => Ok(Self::Security),
            other => {
                Err(BackhandError::InvalidXattrTable(format!("unknown xattr prefix: {other:#x}")))
            }
        }
    }
}

/// A single decoded extended attribute
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    pub prefix: XattrPrefix,
    pub name: String,
    pub value: Vec<u8>,
}

impl Xattr {
    /// Full attribute name including its namespace prefix, e.g. `user.foo`
    pub fn full_name(&self) -> String {
        format!("{}{}", self.prefix.as_str(), self.name)
    }
}

/// Header of the on-disk xattr id table, located at
/// [`crate::v4::squashfs::SuperBlock::xattr_table`]. Immediately followed on-disk by the raw
/// index array of metadata block pointers for the [`XattrId`] entries (same convention as the
/// id/fragment/export lookup tables).
#[derive(Debug, Copy, Clone, PartialEq, Eq, DekuRead, DekuWrite, DekuSize)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct XattrIdTable {
    /// Start of the xattr key/value metadata region
    pub xattr_table_start: u64,
    /// Number of [`XattrId`] entries
    pub xattr_ids: u32,
    pub unused: u32,
}

/// Entry in the xattr id lookup table, one per inode that has xattrs
#[derive(Debug, Copy, Clone, PartialEq, Eq, DekuRead, DekuWrite, DekuSize)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct XattrId {
    /// `(block << 16) | offset` into the xattr key/value metadata region, pointing at the first
    /// of `count` key/value pairs for this inode
    pub xattr: u64,
    /// Number of key/value pairs starting at `xattr`
    pub count: u32,
    /// Uncompressed byte size of the name+value data for this entry
    pub size: u32,
}

impl XattrId {
    pub(crate) const SIZE: usize = Self::SIZE_BYTES.unwrap();
}

/// Key (and inline-value marker) of a single xattr key/value pair
#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct XattrEntry {
    pub xattr_type: u16,
    pub name_size: u16,
    #[deku(count = "*name_size")]
    pub name: Vec<u8>,
}

/// Value of a xattr key/value pair. When `XattrEntry::xattr_type & XATTR_VALUE_OOL == 0`,
/// `value` is the attribute's actual data. When the OOL bit is set, this struct is reused as a
/// wrapper: `vsize` is always [`XATTR_VALUE_OOL_SIZE`] and `value` holds an 8-byte
/// `(block << 16) | offset` reference to the real [`XattrValue`], stored elsewhere in the
/// key/value metadata region (shared with other entries that have the same value).
#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct XattrValue {
    pub vsize: u32,
    #[deku(count = "*vsize")]
    pub value: Vec<u8>,
}

/// Byte size of an OOL reference stored as a [`XattrValue`]'s `value`
pub(crate) const XATTR_VALUE_OOL_SIZE: usize = 8;

/// Cached, parsed xattr id table + key/value metadata region for a filesystem
pub struct XattrTable {
    pub(crate) ids: Vec<XattrId>,
    /// `(offset_from_kv_region_start, offset_in_kv_bytes)`, same convention as
    /// `Squashfs::dir_blocks`
    pub(crate) kv_map: IntMap<u64, u64>,
    pub(crate) kv_bytes: Vec<u8>,
}
