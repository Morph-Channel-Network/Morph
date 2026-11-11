//! Canonical bounded Script dictionaries. References never substitute for an
//! asset/lock commitment: callers still validate every role against its owner.
use crate::multi_asset::{MULTI_ASSET_MAX_SCRIPT_LEN, multi_asset_script_occupied_bytes};
use crate::{Result, ScriptError, read_u16, write_u16};
use alloc::vec::Vec;

pub const MAX_SCRIPTS: usize = 64;
pub const MAX_TABLE_LEN: usize = 4 + MAX_SCRIPTS * (2 + MULTI_ASSET_MAX_SCRIPT_LEN);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptTable<'a> {
    raw: &'a [u8],
    count: usize,
    offsets: [u16; MAX_SCRIPTS + 1],
}
impl<'a> ScriptTable<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 4 || raw.len() > MAX_TABLE_LEN || read_u16(raw, 2) != 0 {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let count = read_u16(raw, 0) as usize;
        if !(1..=MAX_SCRIPTS).contains(&count) {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let mut offsets = [0; MAX_SCRIPTS + 1];
        let mut offset = 4usize;
        let mut previous: Option<&[u8]> = None;
        for slot in offsets.iter_mut().take(count) {
            let prefix = raw
                .get(offset..offset + 2)
                .ok_or(ScriptError::MultiAssetEncoding)?;
            let len = read_u16(prefix, 0) as usize;
            if !(53..=MULTI_ASSET_MAX_SCRIPT_LEN).contains(&len) {
                return Err(ScriptError::MultiAssetEncoding);
            }
            *slot = u16::try_from(offset).map_err(|_| ScriptError::MultiAssetEncoding)?;
            let script = raw
                .get(offset + 2..offset + 2 + len)
                .ok_or(ScriptError::MultiAssetEncoding)?;
            multi_asset_script_occupied_bytes(script)?;
            if previous.is_some_and(|p| p >= script) {
                return Err(ScriptError::MultiAssetEncoding);
            }
            previous = Some(script);
            offset += 2 + len;
        }
        offsets[count] = u16::try_from(offset).map_err(|_| ScriptError::MultiAssetEncoding)?;
        if offset != raw.len() {
            return Err(ScriptError::MultiAssetEncoding);
        }
        Ok(Self {
            raw,
            count,
            offsets,
        })
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn script(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.count {
            return Err(ScriptError::IndexOutOfBounds);
        }
        Ok(&self.raw[self.offsets[index] as usize + 2..self.offsets[index + 1] as usize])
    }
    pub fn index_of(&self, script: &[u8]) -> Result<usize> {
        for i in 0..self.count {
            if self.script(i)? == script {
                return Ok(i);
            }
        }
        Err(ScriptError::MultiAssetCommitmentMismatch)
    }
    pub fn complete_usage(&self) -> u64 {
        if self.count == 64 {
            u64::MAX
        } else {
            (1u64 << self.count) - 1
        }
    }
}

pub fn encode(scripts: &[&[u8]]) -> Result<Vec<u8>> {
    if scripts.is_empty() || scripts.len() > 2 * MAX_SCRIPTS {
        return Err(ScriptError::MultiAssetEncoding);
    }
    let mut values = scripts.to_vec();
    values.sort_unstable();
    values.dedup();
    if values.len() > MAX_SCRIPTS {
        return Err(ScriptError::MultiAssetEncoding);
    }
    let mut raw = alloc::vec![0; 4];
    write_u16(&mut raw, 0, values.len() as u16);
    for script in values {
        multi_asset_script_occupied_bytes(script)?;
        raw.extend_from_slice(&(script.len() as u16).to_le_bytes());
        raw.extend_from_slice(script);
    }
    ScriptTable::parse(&raw)?;
    Ok(raw)
}

/// Scope 0 owns its table; scope 1 uses the enclosing Factory's table. A standalone
/// package never accepts shared scope, and a Factory child never embeds a second table.
pub fn encode_roles(scripts: &[&[u8]], shared: Option<&ScriptTable<'_>>) -> Result<Vec<u8>> {
    if scripts.is_empty() || scripts.len() > 14 {
        return Err(ScriptError::MultiAssetEncoding);
    }
    let owned;
    let table = if let Some(table) = shared {
        *table
    } else {
        owned = encode(scripts)?;
        ScriptTable::parse(&owned)?
    };
    let mut raw = alloc::vec![u8::from(shared.is_some()), scripts.len() as u8, 0, 0];
    if shared.is_none() {
        write_u16(&mut raw, 2, table.as_bytes().len() as u16);
    }
    for script in scripts {
        raw.push(table.index_of(script)? as u8);
    }
    if shared.is_none() {
        raw.extend_from_slice(table.as_bytes());
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn script(seed: u8) -> Vec<u8> {
        let mut raw = alloc::vec![0; 54];
        for (offset, value) in [(0, 54u32), (4, 16), (8, 48), (12, 49), (49, 1)] {
            raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw[16..48].fill(seed);
        raw[48] = 2;
        raw[53] = seed;
        raw
    }
    #[test]
    fn table_has_one_canonical_encoding_and_bounded_references() {
        let a = script(1);
        let b = script(2);
        let raw = encode(&[&b, &a, &b]).unwrap();
        let table = ScriptTable::parse(&raw).unwrap();
        assert_eq!(table.count(), 2);
        assert_eq!(table.script(0).unwrap(), a);
        assert_eq!(table.script(1).unwrap(), b);
        assert!(table.script(2).is_err());
        assert!(table.index_of(&script(3)).is_err());
        assert_eq!(
            encode_roles(&[&b, &a, &b], Some(&table)).unwrap(),
            [1, 3, 0, 0, 1, 0, 1]
        );
        for len in 0..raw.len() {
            assert!(ScriptTable::parse(&raw[..len]).is_err());
        }
        for changed in [
            {
                let mut v = raw.clone();
                v.push(0);
                v
            },
            {
                let mut v = raw.clone();
                v[2] = 1;
                v
            },
            {
                let mut v = raw.clone();
                v[0] = 0;
                v
            },
            {
                let mut v = raw.clone();
                v[0] = 65;
                v
            },
            {
                let mut v = raw.clone();
                v[4..6].copy_from_slice(&513u16.to_le_bytes());
                v
            },
            {
                let mut v = raw.clone();
                v[6..60].copy_from_slice(&b);
                v[62..116].copy_from_slice(&a);
                v
            },
            {
                let mut v = raw.clone();
                v[62..116].copy_from_slice(&a);
                v
            },
        ] {
            assert!(ScriptTable::parse(&changed).is_err());
        }
        let values: Vec<_> = (1..=64).map(script).collect();
        let refs: Vec<_> = values.iter().map(Vec::as_slice).collect();
        let maximum = encode(&refs).unwrap();
        assert_eq!(
            ScriptTable::parse(&maximum).unwrap().complete_usage(),
            u64::MAX
        );
    }
    #[test]
    fn delegation_authority_is_immutable_but_assets_may_use_type_hashes() {
        let mut raw = script(1);
        for hash_type in [0, 2, 4] {
            raw[48] = hash_type;
            crate::multi_asset::require_immutable_authority_script(&raw).unwrap();
        }
        raw[48] = 1;
        crate::multi_asset::multi_asset_script_occupied_bytes(&raw).unwrap();
        assert_eq!(
            crate::multi_asset::require_immutable_authority_script(&raw),
            Err(ScriptError::UnsupportedProtocolProfile)
        );
    }
}
