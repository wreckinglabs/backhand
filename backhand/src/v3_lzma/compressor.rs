use liblzma::stream::{Action, Filters, LzmaOptions, Stream};
use no_std_io2::io::Read;

pub use crate::traits::CompressionAction;
pub use crate::traits::types::Compressor;
use tracing::trace;

/// Byte offsets into a compressed block at which a `props` + `dict_size` +
/// bitstream header may begin. Mirrors sasquatch's `lzma_alt_uncompress`
/// `common_offsets = { 0, 4 }`: most blocks start the header at byte 0, but
/// some squashfs 1.0-derived images (and apparently some v3 `shsq` images)
/// carry 4 bytes of leading cruft before it.
const LZMA_ALT_HEADER_OFFSETS: [usize; 2] = [0, 4];

/// Upper bound, in bytes, on the uncompressed size of any single squashfs
/// block. The format caps `block_log` at 20, so a data block is at most 1 MiB
/// and a metadata block at most `SQUASHFS_METADATA_SIZE` (8 KiB) — both fit
/// here. Clamps the caller-supplied `out.capacity()` (the per-block size
/// ceiling) so a pathological capacity can never drive an oversized allocation.
const MAX_SQUASHFS_BLOCK: usize = 1 << 20;

/// LZMA properties byte for the squashfs-lzma encoder defaults `lc=3, lp=0,
/// pb=2`, packed as `(pb * 5 + lp) * 9 + lc`. Used for the *headerless* raw
/// variant, whose blocks carry no `props`/`dict_size` field.
const SQUASHFS_LZMA_PROPS: u8 = 0x5d;

/// Decompress one raw-LZMA1 squashfs block.
///
/// Some v3 squashfs images (e.g. `shsq` swap images) store every metadata and
/// data block as a bare LZMA1 stream with **no** embedded uncompressed-size
/// field and **no** end-of-stream marker, so the decoder cannot know where the
/// decompressed output ends. Two framings are seen, both handled by the caller:
/// "lzma-alt" (a 1-byte `props` + 4-byte little-endian `dict_size` header, then
/// the range-coded stream) and headerless (the stream directly, with the
/// squashfs encoder's fixed `lc=3/lp=0/pb=2`). Either way, by the time control
/// reaches here `props`/`dict_size`/`payload` describe the bare LZMA1 stream.
///
/// `payload[0]` must be the LZMA range coder's mandatory leading `0x00` byte;
/// requiring it cheaply rejects a wrong framing guess (a header byte that isn't
/// `0x00`) before decoding, so a bad guess fails instead of yielding garbage.
///
/// The length problem is solved with **canonical `liblzma`** (already this
/// crate's xz decompressor) plus the structural size ceiling: decode into an
/// output buffer of exactly `max_out` bytes — the caller's `out.capacity()`,
/// which squashfs sets to `SQUASHFS_METADATA_SIZE` for a metadata block or
/// `block_size` for a data block (the same convention the v4 LZO/LZ4
/// decompressors rely on). A *full* block fills the buffer and stops at exactly
/// `max_out` (dropping the one phantom byte a size-less LZMA1 decode would
/// otherwise emit past the genuine end); a *short* block stops earlier when the
/// compressed input is exhausted, at its true length. Validated byte-for-byte
/// against `liblzma` across every block of real `shsq` firmware. (A pure-Rust
/// `lzma_rust2` attempt could not match this: its read-level EOF handling is
/// off by ±1 at the genuine boundary — it masks EOF as a phantom byte and can
/// fault mid-block on match-splitting.)
fn decompress_raw_lzma1(
    payload: &[u8],
    props: u8,
    dict_size: u32,
    max_out: usize,
    out: &mut Vec<u8>,
) -> bool {
    // The leading byte of a raw LZMA1 range-coded stream is always `0x00`.
    if max_out == 0 || payload.first() != Some(&0x00) {
        return false;
    }

    // Unpack the packed `props` byte into lc/lp/pb (`(pb * 5 + lp) * 9 + lc`).
    let lc = u32::from(props % 9);
    let rem = props / 9;
    let lp = u32::from(rem % 5);
    let pb = u32::from(rem / 5);

    let mut opts = LzmaOptions::new();
    opts.dict_size(dict_size).literal_context_bits(lc).literal_position_bits(lp).position_bits(pb);
    let mut filters = Filters::new();
    filters.lzma1(&opts);
    let Ok(mut stream) = Stream::new_raw_decoder(&filters) else {
        return false;
    };

    // Decode into a buffer capped at the structural block size. liblzma stops
    // when the input is exhausted (short block → true length) or the output
    // fills (full block → exactly `max_out`, dropping the phantom tail byte).
    out.resize(max_out, 0);
    let mut in_off = 0usize;
    let mut out_off = 0usize;
    loop {
        let result = stream.process(&payload[in_off..], &mut out[out_off..], Action::Run);
        let new_in = stream.total_in() as usize;
        let new_out = stream.total_out() as usize;
        let progressed = new_in > in_off || new_out > out_off;
        in_off = new_in;
        out_off = new_out;
        if out_off >= max_out || in_off >= payload.len() || !progressed || result.is_err() {
            break;
        }
    }
    out.truncate(out_off);
    !out.is_empty()
}

#[derive(Copy, Clone)]
pub struct LzmaAdaptiveCompressor;

impl CompressionAction for LzmaAdaptiveCompressor {
    type Error = crate::error::BackhandError;
    type Compressor = Option<Compressor>;
    type FilesystemCompressor = crate::v3::compressor::FilesystemCompressor;
    type SuperBlock = crate::v3::squashfs::SuperBlock;

    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        _compressor: Self::Compressor,
    ) -> Result<(), Self::Error> {
        trace!("v3_lzma decompress");
        if bytes.is_empty() {
            return Ok(());
        }

        // The caller pre-sizes `out`'s capacity to the structural maximum for
        // this block (`SQUASHFS_METADATA_SIZE` or `block_size`); capture it
        // before the standard fallback can grow it. This is the size ceiling
        // the raw lzma-alt path needs to drop the range coder's phantom tail
        // byte on a full block (see `decompress_raw_lzma1`).
        let max_out = out.capacity().min(MAX_SQUASHFS_BLOCK);

        // Standard ".lzma" alone-format blocks (13-byte header carrying a real
        // uncompressed-size field) decode cleanly here. Raw "lzma-alt" blocks
        // misparse their range-coded bytes as that header and fail to produce
        // output, falling through to the raw path below.
        if let Ok(mut reader) = lzma_rust2::LzmaReader::new_mem_limit(bytes, u32::MAX, None) {
            if reader.read_to_end(out).is_ok() && !out.is_empty() {
                trace!("Standard LZMA decompression successful: {} bytes", out.len());
                return Ok(());
            }
            out.clear();
        }

        // "lzma-alt" framing, faithfully ported from sasquatch's
        // `lzma_alt_uncompress`: a `props` byte (lc/lp/pb packed per the
        // standard LZMA SDK convention) followed by a 4-byte little-endian
        // `dict_size`, then a bare LZMA1 bitstream with no embedded
        // uncompressed-size field and no end-of-stream marker. The header may
        // start at byte 0, or 4 bytes in if the block carries leading cruft
        // (`LZMA_ALT_HEADER_OFFSETS`, sasquatch's `common_offsets = {0, 4}`).
        // See `decompress_raw_lzma1` for how the output length is recovered
        // without ever guessing it.
        for &offset in &LZMA_ALT_HEADER_OFFSETS {
            let Some(header) = bytes.get(offset..) else { continue };
            let Some((&props, rest)) = header.split_first() else { continue };
            let Some((dict_size_bytes, payload)) = rest.split_at_checked(4) else { continue };
            let dict_size = u32::from_le_bytes(
                dict_size_bytes.try_into().expect("split_at_checked(4) yields 4 bytes"),
            );
            if decompress_raw_lzma1(payload, props, dict_size, max_out, out) {
                trace!(
                    "lzma-alt decompression successful at header offset {}: {} bytes",
                    offset,
                    out.len()
                );
                return Ok(());
            }
            out.clear();
        }

        // Headerless raw LZMA1: no `props`/`dict_size` field at all — the
        // range-coded stream begins at byte 0 with the squashfs encoder's fixed
        // `lc=3/lp=0/pb=2` (`SQUASHFS_LZMA_PROPS`). Seen in plain v3 LZMA images
        // (e.g. `squashfs_v3_le.lzma`). This is mutually exclusive with the
        // lzma-alt framing above: a raw stream's leading byte is always `0x00`,
        // which is `payload[0]` here but the (≈never-zero) `props` value there,
        // so `decompress_raw_lzma1`'s leading-byte gate rejects a wrong guess
        // rather than yielding garbage. `dict_size` is implicit; the block's own
        // size (`max_out`) bounds every back-reference, so it suffices.
        if decompress_raw_lzma1(bytes, SQUASHFS_LZMA_PROPS, max_out as u32, max_out, out) {
            trace!("headerless raw LZMA1 decompression successful: {} bytes", out.len());
            return Ok(());
        }
        out.clear();

        Err(crate::BackhandError::UnsupportedCompression(
            "Failed to decompress LZMA adaptive data".to_string(),
        ))
    }

    fn compress(
        &self,
        _bytes: &[u8],
        _fc: Self::FilesystemCompressor,
        _block_size: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};

    use super::*;

    /// Encode `plain` as a bare LZMA1 range-coded stream (no header, no size,
    /// the framing squashfs blocks use) with `lc=3/lp=0/pb=2`.
    fn encode_raw_lzma1(plain: &[u8], dict: u32) -> Vec<u8> {
        // `new()` lacks the encoder-required fields; a preset fills them, then
        // we pin the squashfs-default lc/lp/pb and dictionary size.
        let mut opts = LzmaOptions::new_preset(6).unwrap();
        opts.dict_size(dict).literal_context_bits(3).literal_position_bits(0).position_bits(2);
        let mut filters = Filters::new();
        filters.lzma1(&opts);
        let mut stream = Stream::new_raw_encoder(&filters).unwrap();

        let mut comp = vec![0u8; plain.len() + 4096];
        let (mut in_off, mut out_off) = (0usize, 0usize);
        loop {
            let status =
                stream.process(&plain[in_off..], &mut comp[out_off..], Action::Finish).unwrap();
            in_off = stream.total_in() as usize;
            out_off = stream.total_out() as usize;
            if status == Status::StreamEnd {
                break;
            }
            if out_off == comp.len() {
                comp.resize(comp.len() * 2, 0);
            }
        }
        comp.truncate(out_off);
        comp
    }

    fn sample() -> Vec<u8> {
        b"squashfs v3 lzma round-trip sample payload. ".repeat(120)
    }

    /// Short block: cap exceeds the genuine size, so decoding stops at input
    /// exhaustion and yields exactly the original bytes.
    #[test]
    fn raw_lzma1_round_trip_short_block() {
        let plain = sample();
        let comp = encode_raw_lzma1(&plain, 0x10000);
        assert_eq!(comp.first(), Some(&0x00), "range-coded stream starts with 0x00");

        let mut out = Vec::new();
        assert!(decompress_raw_lzma1(
            &comp,
            SQUASHFS_LZMA_PROPS,
            0x10000,
            plain.len() + 4096,
            &mut out
        ));
        assert_eq!(out, plain);
    }

    /// Full block: cap equals the genuine size, so decoding stops at the cap —
    /// dropping the phantom tail byte a size-less LZMA1 decode would emit.
    #[test]
    fn raw_lzma1_round_trip_full_block() {
        let plain = sample();
        let comp = encode_raw_lzma1(&plain, 0x10000);

        let mut out = Vec::new();
        assert!(decompress_raw_lzma1(&comp, SQUASHFS_LZMA_PROPS, 0x10000, plain.len(), &mut out));
        assert_eq!(out, plain);
    }

    /// The leading-byte gate rejects a payload that is not a range-coded stream
    /// (first byte != 0x00) instead of decoding it into garbage.
    #[test]
    fn raw_lzma1_rejects_non_range_coder_lead_byte() {
        let mut out = Vec::new();
        assert!(!decompress_raw_lzma1(
            &[0x01, 0x02, 0x03, 0x04],
            SQUASHFS_LZMA_PROPS,
            0x10000,
            8192,
            &mut out
        ));
        assert!(out.is_empty());
    }

    /// `decompress` dispatches both framings: lzma-alt (`[props][dict][stream]`)
    /// and headerless (stream at byte 0), recovering the original bytes.
    #[test]
    fn decompress_dispatches_both_framings() {
        let plain = sample();
        let comp = encode_raw_lzma1(&plain, 0x10000);
        let comp_decoder = LzmaAdaptiveCompressor;

        // headerless: the range-coded stream directly.
        let mut out = Vec::with_capacity(plain.len() + 4096);
        comp_decoder.decompress(&comp, &mut out, None).unwrap();
        assert_eq!(out, plain, "headerless framing");

        // lzma-alt: props byte + 4-byte little-endian dict_size + stream.
        let mut alt = vec![SQUASHFS_LZMA_PROPS];
        alt.extend_from_slice(&0x10000u32.to_le_bytes());
        alt.extend_from_slice(&comp);
        let mut out = Vec::with_capacity(plain.len() + 4096);
        comp_decoder.decompress(&alt, &mut out, None).unwrap();
        assert_eq!(out, plain, "lzma-alt framing");
    }
}
