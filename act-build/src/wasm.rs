use std::borrow::Cow;

use anyhow::{Result, bail};
use wasm_encoder::{Component, CustomSection};
use wasmparser::{Parser, Payload};

/// Read a custom section from a WASM component by name.
///
/// Returns `Ok(None)` if no custom section with the given name exists.
pub fn read_custom_section<'a>(wasm: &'a [u8], name: &str) -> Result<Option<&'a [u8]>> {
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload?;
        if let Payload::CustomSection(reader) = &payload
            && reader.name() == name
        {
            return Ok(Some(reader.data()));
        }
    }
    Ok(None)
}

/// Set (add or replace) a top-level custom section in a WASM component.
///
/// Scans top-level sections by LEB128 framing (avoids parser recursion into
/// nested modules), then splices the replacement section encoded via `wasm_encoder`.
pub fn set_custom_section(wasm: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    // Validate component header
    if wasm.len() < 8 || &wasm[0..4] != b"\0asm" {
        bail!("not a valid WASM file");
    }
    if wasm[4] != 0x0d {
        bail!(
            "expected a WASM component (layer 0x0d), got 0x{:02x}",
            wasm[4]
        );
    }

    // Find the target section's byte range by scanning top-level section framing.
    let found_range = find_custom_section_range(wasm, name)?;

    // Encode the new custom section via wasm_encoder.
    let new_bytes = encode_custom_section(name, data);

    // Splice into the original WASM.
    let mut result = Vec::with_capacity(wasm.len() + new_bytes.len());
    if let Some(range) = found_range {
        result.extend_from_slice(&wasm[..range.start]);
        result.extend_from_slice(&new_bytes);
        result.extend_from_slice(&wasm[range.end..]);
    } else {
        result.extend_from_slice(wasm);
        result.extend_from_slice(&new_bytes);
    }

    Ok(result)
}

/// Scan top-level section framing to find a custom section by name.
/// Returns byte range (section ID through end of section data) or None.
fn find_custom_section_range(wasm: &[u8], name: &str) -> Result<Option<std::ops::Range<usize>>> {
    let mut pos = 8; // skip component header

    while pos < wasm.len() {
        let section_start = pos;
        let section_id = wasm[pos];
        pos += 1;

        let (section_len, leb_bytes) = read_leb128(&wasm[pos..])?;
        pos += leb_bytes;

        let section_end = pos + section_len as usize;
        if section_end > wasm.len() {
            bail!("section at offset {section_start} extends past end of file");
        }

        if section_id == 0 && matches_custom_section_name(&wasm[pos..section_end], name) {
            return Ok(Some(section_start..section_end));
        }

        pos = section_end;
    }

    Ok(None)
}

/// Check if a custom section's content starts with the given name.
fn matches_custom_section_name(section_data: &[u8], name: &str) -> bool {
    let Ok((name_len, leb_bytes)) = read_leb128(section_data) else {
        return false;
    };
    let name_end = leb_bytes + name_len as usize;
    if name_end > section_data.len() {
        return false;
    }
    std::str::from_utf8(&section_data[leb_bytes..name_end])
        .is_ok_and(|section_name| section_name == name)
}

/// Encode a custom section using wasm_encoder, returning raw section bytes
/// (without component header).
fn encode_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
    let mut component = Component::new();
    component.section(&CustomSection {
        name: Cow::Borrowed(name),
        data: Cow::Borrowed(data),
    });
    let full = component.finish();
    // Strip the 8-byte component header — we only need the raw section bytes.
    full[8..].to_vec()
}

/// Read a LEB128-encoded u32. Returns (value, bytes_consumed).
fn read_leb128(bytes: &[u8]) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 35 {
            bail!("LEB128 overflow");
        }
    }
    bail!("unexpected end of LEB128")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_wasm() -> Vec<u8> {
        Component::new().finish()
    }

    #[test]
    fn add_new_custom_section() {
        let wasm = minimal_wasm();
        let data = b"hello world";

        let result = set_custom_section(&wasm, "test-section", data).unwrap();
        let read_back = read_custom_section(&result, "test-section").unwrap();

        assert_eq!(read_back, Some(data.as_slice()));
    }

    #[test]
    fn replace_existing_custom_section() {
        let wasm = minimal_wasm();
        let original = b"original data";
        let replacement = b"replaced data";

        let with_section = set_custom_section(&wasm, "my-section", original).unwrap();
        assert_eq!(
            read_custom_section(&with_section, "my-section").unwrap(),
            Some(original.as_slice())
        );

        let replaced = set_custom_section(&with_section, "my-section", replacement).unwrap();
        assert_eq!(
            read_custom_section(&replaced, "my-section").unwrap(),
            Some(replacement.as_slice())
        );
    }

    #[test]
    fn read_missing_section_returns_none() {
        let wasm = minimal_wasm();
        let result = read_custom_section(&wasm, "nonexistent").unwrap();
        assert_eq!(result, None);
    }
}
