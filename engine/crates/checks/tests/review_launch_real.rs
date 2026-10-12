//! A chain file of `launch_real`, read back from disk and replayed from its bytes alone.
//!
//! `launch_real` checks its chain while it still holds the objects the chain was built from.
//! This file starts from the other end: it reads a finished chain file, builds every
//! transaction from the transaction fields only, keeps its own set of unspent coins that
//! starts with the funding coin, and puts every transaction to the node rules again. The
//! descriptive fields build nothing: the value, script and covenant id under `spends`, the
//! `role` of a bound output and the `to` of an unbound one are compared with the transaction
//! and the set of coins, and `state` is not read.
//!
//! - a step spends only coins of that set, is accepted on submission and inside a block, has
//!   the id the file states, carries the storage mass a node calculates in its mass field and
//!   pays the fee the file states. That fee is at least the fee rate of the file times the
//!   largest of three numbers: the compute mass, half the transient mass rounded up, and the
//!   storage mass. The whole transient mass is not charged: a step that pays less than the
//!   fee rate on it is printed;
//! - every output without a covenant binding pays the script of one of the three parties, and
//!   every bound output is bound to input 0 under the covenant id of the file;
//! - a probe spends only coins that are unspent after the last step, is refused on submission
//!   and inside a block, and the only input whose script fails is input 0;
//! - the fees of the steps add up to the total the file states and are within its cap.
//!
//! The files read are the two the self-test of `launch_real` writes into the result directory
//! (skipped when they are not there yet) and every file named in `REVIEW_CHAIN_FILES`
//! (separated by `;`, each one required).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use node_gate::{GateOptions, GateParams, evaluate};
use secp256k1::{Keypair, SECP256K1, SecretKey};
use serde_json::Value;

fn num(value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("a whole number, found {value}"))
}

/// The bytes a hex field of the file stands for.
fn unhex(field: &Value) -> Vec<u8> {
    let text = field.as_str().expect("a hex text");
    assert!(
        text.len().is_multiple_of(2) && text.is_ascii(),
        "hex of whole bytes"
    );
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash(value: &Value) -> Hash {
    Hash::from_bytes(<[u8; 32]>::try_from(unhex(value)).expect("32 bytes"))
}

/// The transaction of one entry, from its transaction fields and nothing else.
fn transaction(entry: &Value) -> Transaction {
    let version = u16::try_from(num(&entry["version"])).expect("a version");
    assert_eq!(version, 1, "a covenant transaction is version 1");
    let inputs = entry["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|input| {
            assert_eq!(num(&input["sig_op_count"]), 0);
            TransactionInput::new_with_compute_budget(
                TransactionOutpoint::new(
                    hash(&input["transaction_id"]),
                    u32::try_from(num(&input["index"])).expect("an output index"),
                ),
                unhex(&input["signature_script"]),
                num(&input["sequence"]),
                u16::try_from(num(&input["compute_budget"])).expect("a compute budget"),
            )
        })
        .collect();
    let outputs = entry["outputs"]
        .as_array()
        .expect("outputs")
        .iter()
        .map(|output| {
            let binding = &output["covenant_binding"];
            let binding = (!binding.is_null()).then(|| {
                CovenantBinding::new(
                    u16::try_from(num(&binding["authorizing_input"])).expect("an input index"),
                    hash(&binding["covenant_id"]),
                )
            });
            TransactionOutput::with_covenant(
                num(&output["value"]),
                ScriptPublicKey::from_vec(
                    u16::try_from(num(&output["script_public_key_version"])).expect("a version"),
                    unhex(&output["script_public_key"]),
                ),
                binding,
            )
        })
        .collect();
    let subnetwork = <[u8; 20]>::try_from(unhex(&entry["subnetwork_id"])).expect("20 bytes");
    let tx = Transaction::new(
        version,
        inputs,
        outputs,
        num(&entry["lock_time"]),
        SubnetworkId::from(subnetwork),
        num(&entry["gas"]),
        unhex(&entry["payload"]),
    );
    tx.set_storage_mass(num(&entry["mass"]));
    tx
}

/// An unspent coin: value, script, covenant id.
type Coin = (u64, ScriptPublicKey, Option<Hash>);

fn replay(path: &Path) {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} cannot be read: {error}", path.display()));
    let chain: Value = serde_json::from_str(&text).expect("the chain file is JSON");
    assert_eq!(chain["format"], "kcc20-launch-chain/1");
    assert_eq!(chain["network"], "testnet-10");
    let node = GateParams::testnet10();
    let covenant = chain["covenant_id"].as_str().expect("a covenant id");
    let feerate = num(&chain["feerate"]);

    // The scripts of the three parties, by their hex.
    let mut parties: BTreeMap<String, &str> = BTreeMap::new();
    for party in ["issuer", "alice", "bob"] {
        let script = chain["parties"][party]["script_public_key"]
            .as_str()
            .expect("a party script");
        assert!(
            parties.insert(script.to_string(), party).is_none(),
            "two parties with one script"
        );
    }

    let funding = &chain["funding"];
    let mut unspent: BTreeMap<(String, u32), Coin> = BTreeMap::new();
    unspent.insert(
        (
            hash(&funding["transaction_id"]).to_string(),
            u32::try_from(num(&funding["index"])).expect("an index"),
        ),
        (
            num(&funding["value"]),
            ScriptPublicKey::from_vec(
                u16::try_from(num(&funding["script_public_key_version"])).expect("a version"),
                unhex(&funding["script_public_key"]),
            ),
            None,
        ),
    );

    let steps = chain["steps"].as_array().expect("steps");
    let probes = chain["probes"].as_array().expect("probes");
    assert_eq!((steps.len(), probes.len()), (13, 3));
    let mut fees = 0u64;
    let mut exact_fees = 0usize;
    for (position, entry) in steps.iter().chain(probes).enumerate() {
        let is_step = position < steps.len();
        let name = entry["name"].as_str().expect("a name");
        let tx = transaction(entry);
        let id = tx.id().to_string();
        assert_eq!(
            entry["transaction_id"].as_str(),
            Some(id.as_str()),
            "{name}: the id of the transaction built from the fields"
        );

        // The coins it spends, looked up in the set kept here.
        let mut entries = Vec::new();
        let mut total_in = 0u64;
        for (index, input) in tx.inputs.iter().enumerate() {
            let key = (
                input.previous_outpoint.transaction_id.to_string(),
                input.previous_outpoint.index,
            );
            let coin = unspent.get(&key).unwrap_or_else(|| {
                panic!("{name}: input {index} spends {key:?}, no unspent coin of the chain")
            });
            let spends = &entry["inputs"][index]["spends"];
            assert_eq!(num(&spends["value"]), coin.0, "{name}: spends.value");
            assert_eq!(
                unhex(&spends["script_public_key"]),
                coin.1.script(),
                "{name}: spends.script_public_key"
            );
            assert_eq!(
                num(&spends["script_public_key_version"]),
                u64::from(coin.1.version())
            );
            assert_eq!(
                spends["covenant_id"].as_str().map(str::to_string),
                coin.2.map(|id| id.to_string()),
                "{name}: spends.covenant_id"
            );
            total_in += coin.0;
            entries.push(UtxoEntry::new(coin.0, coin.1.clone(), 1, false, coin.2));
        }

        // Where the outputs go.
        let mut total_out = 0u64;
        for (index, output) in tx.outputs.iter().enumerate() {
            total_out += output.value;
            let described = &entry["outputs"][index];
            let script = hex(output.script_public_key.script());
            match output.covenant {
                Some(binding) => {
                    assert_eq!(binding.covenant_id.to_string(), covenant, "{name}: {index}");
                    assert_eq!(binding.authorizing_input, 0, "{name}: output {index}");
                    assert_eq!(described["role"], "covenant", "{name}: output {index}");
                    assert!(!parties.contains_key(&script), "{name}: output {index}");
                }
                None => {
                    let party = parties.get(&script).unwrap_or_else(|| {
                        panic!("{name}: output {index} pays a script of no party")
                    });
                    assert_eq!(output.script_public_key.version(), 0);
                    assert_eq!(described["to"], *party, "{name}: output {index}");
                }
            }
        }
        let fee = total_in
            .checked_sub(total_out)
            .unwrap_or_else(|| panic!("{name}: the outputs hold more than the inputs"));
        assert_eq!(num(&entry["fee"]), fee, "{name}: the fee");

        let submit = evaluate(&node, &tx, &entries, GateOptions::submit());
        let block = evaluate(&node, &tx, &entries, GateOptions::block());
        if is_step {
            assert!(
                submit.accepted(),
                "{name}: refused on submission: {:?}",
                submit.verdict.first_refusal
            );
            assert!(
                block.accepted(),
                "{name}: refused inside a block: {:?}",
                block.verdict.first_refusal
            );
            assert_eq!(submit.verdict.fee, Some(fee), "{name}: the fee a node sees");
            let masses = submit.verdict.masses.as_ref().expect("masses");
            let storage = masses.calculated_storage_mass.expect("a storage mass");
            assert_eq!(num(&entry["mass"]), storage, "{name}: the mass field");
            // The mass a node charges its fee floor on is the larger of the compute mass and
            // half the transient mass, rounded up (`normalized_transient_mass` in the policy
            // module of `node-gate`). The fee of a step must cover the fee rate on the larger
            // of that mass and the storage mass. The whole transient mass is not charged: a
            // step that pays less than the fee rate on it is printed.
            let floor_mass = masses.compute_mass.max(masses.transient_mass.div_ceil(2));
            let charged = floor_mass.max(storage);
            assert!(
                fee >= feerate * charged,
                "{name}: the fee of {fee} is below {feerate} x {charged}"
            );
            exact_fees += usize::from(fee == feerate * charged);
            if fee < feerate * masses.transient_mass {
                println!(
                    "  {name}: the fee is {} sompi per gram of its transient mass of {}",
                    fee / masses.transient_mass,
                    masses.transient_mass
                );
            }

            for input in &tx.inputs {
                let key = (
                    input.previous_outpoint.transaction_id.to_string(),
                    input.previous_outpoint.index,
                );
                unspent.remove(&key).expect("spent once");
            }
            for (index, output) in tx.outputs.iter().enumerate() {
                unspent.insert(
                    (id.clone(), index as u32),
                    (
                        output.value,
                        output.script_public_key.clone(),
                        output.covenant.map(|binding| binding.covenant_id),
                    ),
                );
            }
            fees += fee;
        } else {
            assert!(!submit.accepted(), "{name}: accepted on submission");
            assert!(!block.accepted(), "{name}: accepted inside a block");
            let failed: Vec<usize> = submit
                .committed_runs
                .iter()
                .enumerate()
                .filter(|(_, run)| run.error().is_some())
                .map(|(index, _)| index)
                .collect();
            assert_eq!(
                failed,
                vec![0],
                "{name}: the inputs whose scripts fail ({} were run)",
                submit.committed_runs.len()
            );
            assert_eq!(submit.committed_runs.len(), tx.inputs.len());
        }
    }
    assert_eq!(num(&chain["totals"]["fees"]), fees, "the fees of the steps");
    assert!(
        fees <= num(&chain["fee_cap_total"]),
        "the fees are within the cap"
    );
    println!(
        "{}: 13 steps accepted, 3 probes refused at input 0; fees {fees}; {exact_fees} of 13 \
         fees are exactly the fee rate times the larger of the fee mass and the storage mass; \
         {} coins unspent",
        path.display(),
        unspent.len()
    );
}

#[test]
fn a_chain_file_replays_from_its_bytes_alone() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let mut replayed = 0;
    let directory = checks::results::results_dir();
    for feerate in [955, 100] {
        let path = directory.join(format!("launch-real-selftest-{feerate}.chain.json"));
        if path.exists() {
            replay(&path);
            replayed += 1;
        }
    }
    if let Some(named) = std::env::var_os("REVIEW_CHAIN_FILES") {
        for path in named.to_string_lossy().split(';').filter(|p| !p.is_empty()) {
            replay(&PathBuf::from(path));
            replayed += 1;
        }
    }
    println!("{replayed} chain files replayed");
}

/// What the pinned secp256k1 shows of a secret under `{:?}`: a short hash, never the bytes.
#[test]
fn the_debug_form_of_a_secret_key_does_not_hold_its_bytes() {
    let secret_bytes = *blake3::hash(b"review_launch_real: a made-up secret key").as_bytes();
    let secret = SecretKey::from_slice(&secret_bytes).expect("a valid secret key");
    let pair = Keypair::from_secret_key(SECP256K1, &secret);
    let shown = format!("{secret:?} {pair:?}").to_lowercase();
    let secret_hex = hex(&secret_bytes);
    for start in (0..=56).step_by(2) {
        assert!(
            !shown.contains(&secret_hex[start..start + 8]),
            "four bytes of the key in its debug form"
        );
    }
    println!("{shown}");
}
