//! Deterministic one-wallet CKB/xUDT transfer preparation. All amounts remain integers.
use crate::keystore::UnlockedKey;
use anyhow::{Result, anyhow, ensure};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed,
    prelude::*,
};
use morph_core::blake2b256;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct Coin {
    pub out_point: packed::OutPoint,
    pub output: packed::CellOutput,
    pub data: Bytes,
}
#[derive(Clone, Debug)]
pub struct Token {
    pub script: packed::Script,
    pub dep: packed::CellDep,
}
#[derive(Clone, Debug)]
pub struct Transfer {
    pub recipient: packed::Script,
    /// Shannons for CKB, base units for xUDT. Decimals are a display policy only.
    pub amount: u128,
    pub token: Option<Token>,
    pub fee_rate: u64,
    pub max_fee: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferSummary {
    pub transaction_hash: String,
    pub amount: String,
    pub token_type_hash: Option<String>,
    pub recipient_lock_hash: String,
    pub fee: String,
    pub recipient_capacity: String,
    pub change_capacity: String,
    pub token_change: String,
    pub input_count: usize,
    pub bytes: usize,
}
/// Constructors are private: callers cannot swap outputs or fee after review.
#[derive(Clone)]
pub struct PreparedTransfer {
    tx: TransactionView,
    coins: Vec<Coin>,
    owner: packed::Script,
    summary: TransferSummary,
}
impl PreparedTransfer {
    pub fn summary(&self) -> &TransferSummary {
        &self.summary
    }
    pub fn transaction(&self) -> &TransactionView {
        &self.tx
    }
    pub fn coins(&self) -> &[Coin] {
        &self.coins
    }
    pub fn sign(&self, key: &UnlockedKey) -> Result<TransactionView> {
        ensure!(key.lock_script()? == self.owner, "wallet.wrong_signer");
        // One lock group, one WitnessArgs + an empty witness per remaining input.
        let mut message = Vec::new();
        message.extend_from_slice(self.tx.hash().as_slice());
        for witness in self.tx.witnesses().into_iter() {
            let raw = witness.raw_data();
            message.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            message.extend_from_slice(&raw);
        }
        let signature = key.sign_digest(blake2b256(&message))?;
        let first = packed::WitnessArgs::new_builder()
            .lock(Some(Bytes::copy_from_slice(&signature)).pack())
            .build();
        let witnesses = std::iter::once(first.as_bytes().pack())
            .chain((1..self.coins.len()).map(|_| Bytes::new().pack()))
            .collect::<Vec<packed::Bytes>>();
        Ok(self
            .tx
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build())
    }
}
fn capacity(output: &packed::CellOutput) -> u64 {
    output.capacity().unpack()
}
fn minimum(output: &packed::CellOutput, data: &Bytes) -> Result<u64> {
    Ok(output
        .occupied_capacity(Capacity::bytes(data.len())?)?
        .as_u64())
}
fn output(
    lock: packed::Script,
    token: Option<packed::Script>,
    data: Bytes,
    requested: Option<u64>,
) -> Result<(packed::CellOutput, Bytes)> {
    let output = packed::CellOutput::new_builder()
        .lock(lock)
        .type_(token.pack())
        .build();
    let min = minimum(&output, &data)?;
    let cap = requested.unwrap_or(min);
    ensure!(cap >= min, "wallet.below_occupied_capacity");
    Ok((output.as_builder().capacity(cap).build(), data))
}
fn token_amount(coin: &Coin, token: &Token) -> Result<Option<u128>> {
    if coin.output.type_().to_opt().as_ref() != Some(&token.script) {
        return Ok(None);
    }
    ensure!(coin.data.len() == 16, "wallet.unsupported_token_data");
    Ok(Some(u128::from_le_bytes(coin.data.as_ref().try_into()?)))
}
pub fn prepare(
    owner: &packed::Script,
    secp_dep: packed::CellDep,
    coins: &[Coin],
    reserved: &BTreeSet<Vec<u8>>,
    request: &Transfer,
) -> Result<PreparedTransfer> {
    ensure!(request.amount > 0, "wallet.amount_positive");
    ensure!(
        (1..=100_000).contains(&request.fee_rate) && request.max_fee > 0,
        "wallet.fee_policy"
    );
    ensure!(coins.len() <= 4096, "wallet.too_many_cells");
    let mut ordered = coins.to_vec();
    ordered.sort_by_key(|c| c.out_point.as_slice().to_vec());
    ensure!(
        ordered.windows(2).all(|v| v[0].out_point != v[1].out_point),
        "wallet.duplicate_input"
    );
    let mut selected = Vec::new();
    let mut plain = Vec::new();
    let mut tokens = 0u128;
    let mut total = 0u64;
    for coin in ordered {
        ensure!(coin.output.lock() == *owner, "wallet.foreign_input");
        ensure!(
            capacity(&coin.output) >= minimum(&coin.output, &coin.data)?,
            "wallet.invalid_input_capacity"
        );
        if reserved.contains(coin.out_point.as_slice()) {
            continue;
        }
        if coin.output.type_().is_none() && coin.data.is_empty() {
            plain.push(coin);
        } else if let Some(token) = &request.token
            && let Some(quantity) = token_amount(&coin, token)?
            && tokens < request.amount
        {
            tokens = tokens
                .checked_add(quantity)
                .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
            total = total
                .checked_add(capacity(&coin.output))
                .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
            selected.push(coin);
        }
    }
    let mut outputs = Vec::new();
    if let Some(token) = &request.token {
        ensure!(tokens >= request.amount, "wallet.insufficient_tokens");
        outputs.push(output(
            request.recipient.clone(),
            Some(token.script.clone()),
            Bytes::copy_from_slice(&request.amount.to_le_bytes()),
            None,
        )?);
        if tokens > request.amount {
            outputs.push(output(
                owner.clone(),
                Some(token.script.clone()),
                Bytes::copy_from_slice(&(tokens - request.amount).to_le_bytes()),
                None,
            )?);
        }
    } else {
        let amount =
            u64::try_from(request.amount).map_err(|_| anyhow!("wallet.amount_overflow"))?;
        outputs.push(output(
            request.recipient.clone(),
            None,
            Bytes::new(),
            Some(amount),
        )?);
    }
    let spent = outputs.iter().try_fold(0u64, |sum, (o, _)| {
        sum.checked_add(capacity(o))
            .ok_or_else(|| anyhow!("wallet.amount_overflow"))
    })?;
    let change_template = output(owner.clone(), None, Bytes::new(), None)?;
    let change_min = capacity(&change_template.0);
    let mut plain = plain.into_iter();
    loop {
        ensure!(selected.len() <= 64, "wallet.too_many_inputs");
        if !selected.is_empty() && total >= spent {
            let mut with_change = outputs.clone();
            with_change.push(change_template.clone());
            let candidate = build(&selected, &with_change, &secp_dep, request.token.as_ref());
            let size = candidate.data().serialized_size_in_block();
            let fee = (size as u64)
                .checked_mul(request.fee_rate)
                .and_then(|v| v.checked_add(999))
                .ok_or_else(|| anyhow!("wallet.fee_overflow"))?
                / 1000;
            ensure!(fee <= request.max_fee, "wallet.fee_above_limit");
            if let Some(change) = total.checked_sub(spent).and_then(|v| v.checked_sub(fee))
                && change >= change_min
            {
                let last = with_change.len() - 1;
                with_change[last].0 = with_change[last]
                    .0
                    .clone()
                    .as_builder()
                    .capacity(change)
                    .build();
                let tx = build(&selected, &with_change, &secp_dep, request.token.as_ref());
                return complete(tx, selected, owner, request, fee, change, tokens, &outputs);
            }
            // Exact-spend is allowed; a sub-minimum change cell is never silently donated as fee.
            let candidate = build(&selected, &outputs, &secp_dep, request.token.as_ref());
            let required = (candidate.data().serialized_size_in_block() as u64)
                .checked_mul(request.fee_rate)
                .and_then(|v| v.checked_add(999))
                .ok_or_else(|| anyhow!("wallet.fee_overflow"))?
                / 1000;
            if total.checked_sub(spent) == Some(required) && required <= request.max_fee {
                return complete(
                    candidate, selected, owner, request, required, 0, tokens, &outputs,
                );
            }
        }
        let coin = plain
            .next()
            .ok_or_else(|| anyhow!("wallet.insufficient_capacity_with_change"))?;
        total = total
            .checked_add(capacity(&coin.output))
            .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
        selected.push(coin);
    }
}
fn build(
    coins: &[Coin],
    outputs: &[(packed::CellOutput, Bytes)],
    secp: &packed::CellDep,
    token: Option<&Token>,
) -> TransactionView {
    let mut deps = vec![secp.clone()];
    if let Some(token) = token
        && token.dep != *secp
    {
        deps.push(token.dep.clone());
    }
    let first = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0; 65])).pack())
        .build()
        .as_bytes();
    let witnesses = std::iter::once(first.pack())
        .chain((1..coins.len()).map(|_| Bytes::new().pack()))
        .collect::<Vec<packed::Bytes>>();
    TransactionBuilder::default()
        .set_cell_deps(deps)
        .set_inputs(
            coins
                .iter()
                .map(|c| packed::CellInput::new(c.out_point.clone(), 0))
                .collect(),
        )
        .set_outputs(outputs.iter().map(|(o, _)| o.clone()).collect())
        .set_outputs_data(outputs.iter().map(|(_, d)| d.pack()).collect())
        .set_witnesses(witnesses)
        .build()
}
#[allow(clippy::too_many_arguments)]
fn complete(
    tx: TransactionView,
    coins: Vec<Coin>,
    owner: &packed::Script,
    request: &Transfer,
    fee: u64,
    change: u64,
    tokens: u128,
    outputs: &[(packed::CellOutput, Bytes)],
) -> Result<PreparedTransfer> {
    let summary = TransferSummary {
        transaction_hash: format!("{:#x}", tx.hash()),
        amount: request.amount.to_string(),
        token_type_hash: request
            .token
            .as_ref()
            .map(|t| format!("{:#x}", t.script.calc_script_hash())),
        recipient_lock_hash: format!("{:#x}", request.recipient.calc_script_hash()),
        fee: fee.to_string(),
        recipient_capacity: capacity(&outputs[0].0).to_string(),
        change_capacity: change.to_string(),
        token_change: request
            .token
            .as_ref()
            .map_or(0, |_| tokens - request.amount)
            .to_string(),
        input_count: coins.len(),
        bytes: tx.data().serialized_size_in_block(),
    };
    Ok(PreparedTransfer {
        tx,
        coins,
        owner: owner.clone(),
        summary,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn coin(
        owner: &packed::Script,
        index: u32,
        ckb: u64,
        token: Option<packed::Script>,
        quantity: Option<u128>,
    ) -> Coin {
        Coin {
            out_point: packed::OutPoint::new([7u8; 32].pack(), index),
            output: packed::CellOutput::new_builder()
                .capacity(ckb * 100_000_000)
                .lock(owner.clone())
                .type_(token.pack())
                .build(),
            data: quantity.map_or_else(Bytes::new, |n| Bytes::copy_from_slice(&n.to_le_bytes())),
        }
    }
    #[test]
    fn ckb_selection_preserves_data_cells_and_exact_fee_and_signs_only_owner() {
        let key = UnlockedKey::generate().unwrap();
        let owner = key.lock_script().unwrap();
        let recipient = owner
            .clone()
            .as_builder()
            .args(Bytes::from(vec![6; 20]).pack())
            .build();
        let request = Transfer {
            recipient,
            amount: 100 * 100_000_000,
            token: None,
            fee_rate: 1000,
            max_fee: 100_000,
        };
        let coins = vec![
            coin(&owner, 0, 400, None, None),
            coin(&owner, 1, 300, None, Some(4)),
        ];
        let prepared = prepare(
            &owner,
            Default::default(),
            &coins,
            &BTreeSet::new(),
            &request,
        )
        .unwrap();
        assert_eq!(prepared.coins.len(), 1);
        let outputs = prepared
            .tx
            .outputs()
            .into_iter()
            .map(|o| capacity(&o))
            .sum::<u64>();
        assert_eq!(
            400 * 100_000_000 - outputs,
            prepared.summary.fee.parse::<u64>().unwrap()
        );
        let signed = prepared.sign(&key).unwrap();
        assert_eq!(signed.hash(), prepared.tx.hash());
        assert_ne!(
            signed.witnesses().as_slice(),
            prepared.tx.witnesses().as_slice()
        );
        assert!(prepared.sign(&UnlockedKey::generate().unwrap()).is_err());
        let reserved = BTreeSet::from([coins[0].out_point.as_slice().to_vec()]);
        assert!(prepare(&owner, Default::default(), &coins, &reserved, &request).is_err());
    }
    #[test]
    fn tokens_are_conserved_per_type_and_foreign_inputs_and_dust_are_rejected() {
        let owner = UnlockedKey::generate().unwrap().lock_script().unwrap();
        let script = packed::Script::new_builder()
            .code_hash([4u8; 32].pack())
            .hash_type(1u8)
            .args(Bytes::from(vec![2; 32]).pack())
            .build();
        let token = Token {
            script: script.clone(),
            dep: Default::default(),
        };
        let request = Transfer {
            recipient: owner.clone(),
            amount: u128::MAX - 2,
            token: Some(token),
            fee_rate: 1000,
            max_fee: 100_000,
        };
        let coins = vec![
            coin(&owner, 0, 500, Some(script), Some(u128::MAX)),
            coin(&owner, 1, 100, None, None),
        ];
        let prepared = prepare(
            &owner,
            Default::default(),
            &coins,
            &BTreeSet::new(),
            &request,
        )
        .unwrap();
        let total = prepared
            .tx
            .outputs_data()
            .into_iter()
            .filter(|v| v.raw_data().len() == 16)
            .map(|v| u128::from_le_bytes(v.raw_data().as_ref().try_into().unwrap()))
            .sum::<u128>();
        assert_eq!(total, u128::MAX);
        assert_eq!(prepared.summary.token_change, "2");
        let mut wrong = coins.clone();
        wrong[0].output = wrong[0]
            .output
            .clone()
            .as_builder()
            .lock(packed::Script::default())
            .build();
        assert!(
            prepare(
                &owner,
                Default::default(),
                &wrong,
                &BTreeSet::new(),
                &request
            )
            .is_err()
        );
        let dust = Transfer {
            recipient: owner.clone(),
            amount: 1,
            token: None,
            fee_rate: 1000,
            max_fee: 100_000,
        };
        assert!(prepare(&owner, Default::default(), &coins, &BTreeSet::new(), &dust).is_err());
    }
}
