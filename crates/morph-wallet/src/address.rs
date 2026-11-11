use anyhow::{Result, ensure};
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}
impl Network {
    pub fn hrp(self) -> &'static str {
        if self == Self::Mainnet { "ckb" } else { "ckt" }
    }
}
/// RFC 21 full-format addresses; code hash and args remain exact Script bytes.
pub fn encode(lock: &packed::Script, network: Network) -> Result<String> {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(lock.code_hash().as_slice());
    bytes.push(lock.hash_type().as_slice()[0]);
    bytes.extend_from_slice(&lock.args().raw_data());
    Ok(bech32::encode::<Bech32m>(
        Hrp::parse(network.hrp())?,
        &bytes,
    )?)
}
pub fn decode(text: &str, network: Network) -> Result<packed::Script> {
    ensure!(text.len() <= 2048, "wallet.address_too_long");
    let checked = CheckedHrpstring::new::<Bech32m>(text)
        .map_err(|_| anyhow::anyhow!("wallet.address_format"))?;
    ensure!(
        checked.hrp() == Hrp::parse(network.hrp())?,
        "wallet.address_network_mismatch"
    );
    let bytes = checked.byte_iter().collect::<Vec<_>>();
    ensure!(bytes.len() >= 34 && bytes[0] == 0, "wallet.address_format");
    ensure!(
        matches!(bytes[33], 0 | 1 | 2 | 4),
        "wallet.address_hash_type"
    );
    Ok(packed::Script::new_builder()
        .code_hash(packed::Byte32::from_slice(&bytes[1..33])?)
        .hash_type(bytes[33])
        .args(Bytes::copy_from_slice(&bytes[34..]).pack())
        .build())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_address_keeps_script_and_rejects_other_network_and_wrong_checksum() {
        let lock = packed::Script::new_builder()
            .code_hash([7u8; 32].pack())
            .hash_type(1u8)
            .args(Bytes::from(vec![8; 20]).pack())
            .build();
        let text = encode(&lock, Network::Testnet).unwrap();
        assert_eq!(decode(&text, Network::Testnet).unwrap(), lock);
        assert!(decode(&text, Network::Mainnet).is_err());
        let bytes = CheckedHrpstring::new::<Bech32m>(&text)
            .unwrap()
            .byte_iter()
            .collect::<Vec<_>>();
        let bad = bech32::encode::<bech32::Bech32>(Hrp::parse("ckt").unwrap(), &bytes).unwrap();
        assert!(decode(&bad, Network::Testnet).is_err());
    }
}
