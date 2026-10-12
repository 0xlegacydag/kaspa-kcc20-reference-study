//! Upstream's own unit tests of the context-free and header-context transaction rules,
//! re-run against the ports in `node_gate::isolation` and `node_gate::header`.
//!
//! What is upstream's: every transaction, every byte vector and every expected result of
//! the two tests `validate_tx_in_isolation_test` and `check_transaction_subnetwork_shape`.
//! They are taken from rusty-kaspa, revision a41a333,
//! consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs:236-500
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers). The transactions are test
//! vectors of that file. They were read from the source offline and are never sent
//! anywhere: every test here validates in memory.
//!
//! What is not upstream's: the way the questions are put. Upstream builds a
//! `TransactionValidator` from the fields of `Params`; the ports read the same fields from
//! `Params` directly, so the same `Params` value is handed to both. Each upstream
//! assertion appears once for the ported function and, where the gate can be asked the
//! same question, once more for `gate::evaluate`, whose step-by-step walk must stop at the
//! same rule. Some errors that upstream matches with wildcards are matched with their
//! values here. The block marked "Not in upstream" inside the first test and the last two
//! tests of the file (`the_isolation_limit_of_a_signature_script_follows_the_fork_schedule`
//! and `a_coinbase_in_a_block_is_not_judged_by_the_amounts_rule`) are additions; they
//! reuse upstream's two transactions.

use kaspa_consensus_core::{
    config::params::{ForkActivation, MAINNET_PARAMS, Params},
    constants::{TX_VERSION, TX_VERSION_TOCCATA},
    errors::tx::TxRuleError,
    subnets::{
        SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_SIZE, SUBNETWORK_NAMESPACE_LEN,
        SUBNETWORK_ZERO_TAIL_LEN, SubnetworkId,
    },
    tx::{
        ComputeCommit, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
        TransactionOutpoint, TransactionOutput,
    },
};
use node_gate::{
    GateOptions, GateParams, Stage,
    gate::{self, Evaluation},
    header::{self, LockTimeArg},
    isolation,
};

/// `assert!(matches!(..))` that prints the value on failure.
macro_rules! assert_matches {
    ($value:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {{
        let value = $value;
        assert!(
            matches!(value, $pattern $(if $guard)?),
            "{:?} does not match {}",
            value,
            stringify!($pattern)
        );
    }};
}

/// The parameters upstream's test builds its validator from: mainnet with at most ten
/// inputs and fifteen outputs (tx_validation_in_isolation.rs:238-250).
fn test_params() -> Params {
    let mut params = MAINNET_PARAMS.clone();
    params.max_tx_inputs = 10;
    params.max_tx_outputs = 15;
    params
}

/// The gate's question for `params` at DAA score zero, which is before Toccata on mainnet.
fn gate_at_zero(params: &Params) -> GateParams {
    GateParams {
        params: params.clone(),
        pov_daa_score: 0,
        block_daa_score: 0,
        past_median_time: 0,
    }
}

/// tx_validation_in_isolation.rs:252-270.
fn valid_coinbase() -> Transaction {
    Transaction::new(
        0,
        vec![],
        vec![TransactionOutput {
            value: 0x12a05f200,
            script_public_key: ScriptPublicKey::from_vec(
                0,
                vec![
                    0xa9, 0x14, 0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56,
                    0x99, 0x71, 0xc7, 0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b, 0x87,
                ],
            ),
            covenant: None,
        }],
        0,
        SUBNETWORK_ID_COINBASE,
        0,
        vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
}

/// tx_validation_in_isolation.rs:274-336.
fn valid_tx() -> Transaction {
    Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_slice(&[
                    0x03, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05,
                    0x56, 0xdc, 0xac, 0xc4, 0x1d, 0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac,
                    0x88, 0xfd, 0xf3, 0x57, 0xa1, 0x87,
                ]),
                index: 0,
            },
            signature_script: vec![
                0x49, // OP_DATA_73
                0x30, 0x46, 0x02, 0x21, 0x00, 0xc3, 0x52, 0xd3, 0xdd, 0x99, 0x3a, 0x98, 0x1b, 0xeb,
                0xa4, 0xa6, 0x3a, 0xd1, 0x5c, 0x20, 0x92, 0x75, 0xca, 0x94, 0x70, 0xab, 0xfc, 0xd5,
                0x7d, 0xa9, 0x3b, 0x58, 0xe4, 0xeb, 0x5d, 0xce, 0x82, 0x02, 0x21, 0x00, 0x84, 0x07,
                0x92, 0xbc, 0x1f, 0x45, 0x60, 0x62, 0x81, 0x9f, 0x15, 0xd3, 0x3e, 0xe7, 0x05, 0x5c,
                0xf7, 0xb5, 0xee, 0x1a, 0xf1, 0xeb, 0xcc, 0x60, 0x28, 0xd9, 0xcd, 0xb1, 0xc3, 0xaf,
                0x77, 0x48, 0x01, // 73-byte signature
                0x41, // OP_DATA_65
                0x04, 0xf4, 0x6d, 0xb5, 0xe9, 0xd6, 0x1a, 0x9d, 0xc2, 0x7b, 0x8d, 0x64, 0xad, 0x23,
                0xe7, 0x38, 0x3a, 0x4e, 0x6c, 0xa1, 0x64, 0x59, 0x3c, 0x25, 0x27, 0xc0, 0x38, 0xc0,
                0x85, 0x7e, 0xb6, 0x7e, 0xe8, 0xe8, 0x25, 0xdc, 0xa6, 0x50, 0x46, 0xb8, 0x2c, 0x93,
                0x31, 0x58, 0x6c, 0x82, 0xe0, 0xfd, 0x1f, 0x63, 0x3f, 0x25, 0xf8, 0x7c, 0x16, 0x1b,
                0xc6, 0xf8, 0xa6, 0x30, 0x12, 0x1d, 0xf2, 0xb3, 0xd3, // 65-byte pubkey
            ],
            sequence: u64::MAX,
            compute_commit: ComputeCommit::SigopCount(0.into()),
        }],
        vec![
            TransactionOutput {
                value: 0x2123e300,
                script_public_key: ScriptPublicKey::from_vec(
                    0,
                    vec![
                        0x76, // OP_DUP
                        0xa9, // OP_HASH160
                        0x14, // OP_DATA_20
                        0xc3, 0x98, 0xef, 0xa9, 0xc3, 0x92, 0xba, 0x60, 0x13, 0xc5, 0xe0, 0x4e,
                        0xe7, 0x29, 0x75, 0x5e, 0xf7, 0xf5, 0x8b, 0x32,
                        0x88, // OP_EQUALVERIFY
                        0xac, // OP_CHECKSIG
                    ],
                ),
                covenant: None,
            },
            TransactionOutput {
                value: 0x108e20f00,
                script_public_key: ScriptPublicKey::from_vec(
                    0,
                    vec![
                        0x76, // OP_DUP
                        0xa9, // OP_HASH160
                        0x14, // OP_DATA_20
                        0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77,
                        0xda, 0x2c, 0x2f, 0x6b, 0x52, 0xde, 0x3d, 0x7c,
                        0x88, // OP_EQUALVERIFY
                        0xac, // OP_CHECKSIG
                    ],
                ),
                covenant: None,
            },
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    )
}

/// The gate's walk for a transaction whose coins are not supplied, in both modes. A
/// transaction refused in isolation never gets to its coins, so none are needed.
fn walks(params: &Params, tx: &Transaction) -> [Evaluation; 2] {
    let gate = gate_at_zero(params);
    [
        gate::evaluate(&gate, tx, &[], GateOptions::block()),
        gate::evaluate(&gate, tx, &[], GateOptions::submit()),
    ]
}

/// Asserts the ported function and both walks of the gate answer with an error matching
/// the pattern, and that the walks stopped in isolation.
macro_rules! assert_refused_in_isolation {
    ($params:expr, $tx:expr, $pattern:pat) => {{
        assert_matches!(
            isolation::validate_tx_in_isolation($params, $tx),
            Err($pattern)
        );
        for evaluation in walks($params, $tx) {
            assert_eq!(evaluation.verdict.harness_error, None);
            assert_eq!(evaluation.verdict.stage_reached, Stage::Isolation);
            assert!(!evaluation.verdict.consensus_accepted);
            assert_matches!(evaluation.consensus_error, Some($pattern));
        }
    }};
}

/// tx_validation_in_isolation.rs:236-416.
#[test]
fn validate_tx_in_isolation_test() {
    let params = test_params();
    let valid_cb = valid_coinbase();
    isolation::validate_tx_in_isolation(&params, &valid_cb).unwrap();

    let valid_tx = valid_tx();
    isolation::validate_tx_in_isolation(&params, &valid_tx).unwrap();
    // The walk leaves isolation behind and asks for the coin.
    for evaluation in walks(&params, &valid_tx) {
        assert_eq!(evaluation.verdict.stage_reached, Stage::UtxoPopulation);
        assert_eq!(
            evaluation.consensus_error,
            Some(TxRuleError::MissingTxOutpoints)
        );
    }

    let mut tx: Transaction = valid_tx.clone();
    tx.subnetwork_id = SubnetworkId::from_byte(3);
    assert_refused_in_isolation!(&params, &tx, TxRuleError::SubnetworksDisabled(_));

    let mut tx = valid_tx.clone();
    tx.inputs = vec![];
    assert_refused_in_isolation!(&params, &tx, TxRuleError::NoTxInputs);

    let mut tx = valid_tx.clone();
    tx.inputs = (0..params.max_tx_inputs + 1)
        .map(|_| valid_tx.inputs[0].clone())
        .collect();
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TooManyInputs(11, 10));

    let mut tx = valid_tx.clone();
    tx.inputs[0].signature_script = vec![0; params.max_signature_script_len().upper_bound() + 1];
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TooBigSignatureScript(0, 250_000));

    // tx_validation_in_isolation.rs:356-375. A signature script one byte above the
    // pre-fork limit passes in isolation and is refused in header context on the
    // pre-fork side only.
    let mut forked_params = params.clone();
    forked_params.toccata_activation = ForkActivation::new(100);
    let mut tx = valid_tx.clone();
    tx.inputs[0].signature_script = vec![0; forked_params.prior_max_signature_script_len + 1];
    assert_matches!(
        isolation::validate_tx_in_isolation(&forked_params, &tx),
        Ok(())
    );
    assert_matches!(
        header::validate_tx_in_header_context(&forked_params, &tx, LockTimeArg::Finalized, 99),
        Err(TxRuleError::TooBigSignatureScript(0, 10_000))
    );
    assert_matches!(
        header::validate_tx_in_header_context(&forked_params, &tx, LockTimeArg::Finalized, 100),
        Ok(())
    );
    // The same two questions put to the walk: DAA score 99 stops in header context, DAA
    // score 100 goes on to the coins.
    for (daa_score, stage) in [(99, Stage::HeaderContext), (100, Stage::UtxoPopulation)] {
        let gate = gate_at_zero(&forked_params).with_daa_score(daa_score);
        for options in [GateOptions::block(), GateOptions::submit()] {
            let evaluation = gate::evaluate(&gate, &tx, &[], options);
            assert_eq!(
                evaluation.verdict.stage_reached, stage,
                "DAA score {daa_score}"
            );
        }
    }

    let mut tx = valid_tx.clone();
    tx.outputs = (0..params.max_tx_outputs + 1)
        .map(|_| valid_tx.outputs[0].clone())
        .collect();
    // Upstream reports `max_tx_inputs` in the second field (line 72).
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TooManyOutputs(16, 10));

    // Not in upstream: the neighbours that tell the two limits apart. On every network
    // both are 1000, so only parameters like these can show which limit a count is
    // compared with. Fifteen outputs pass although the input limit is ten; ten distinct
    // inputs pass and the eleventh is refused although the output limit is fifteen.
    let mut tx = valid_tx.clone();
    tx.outputs = (0..params.max_tx_outputs)
        .map(|_| valid_tx.outputs[0].clone())
        .collect();
    assert_matches!(isolation::validate_tx_in_isolation(&params, &tx), Ok(()));
    let distinct_inputs = |count: usize| {
        let mut tx = valid_tx.clone();
        tx.inputs = (0..count as u32)
            .map(|index| {
                let mut input = valid_tx.inputs[0].clone();
                input.previous_outpoint.index = index;
                input
            })
            .collect();
        tx
    };
    assert_matches!(
        isolation::validate_tx_in_isolation(&params, &distinct_inputs(10)),
        Ok(())
    );
    assert_refused_in_isolation!(
        &params,
        &distinct_inputs(11),
        TxRuleError::TooManyInputs(11, 10)
    );
    // The check a mempool makes before it calculates the masses reports the output limit
    // itself (consensus/src/consensus/mod.rs:608-610); the in-isolation rule the input limit.
    let mut tx = valid_tx.clone();
    tx.outputs = (0..params.max_tx_outputs + 1)
        .map(|_| valid_tx.outputs[0].clone())
        .collect();
    let submitted = gate::evaluate(&gate_at_zero(&params), &tx, &[], GateOptions::submit());
    assert_eq!(
        submitted.pre_mass_error,
        Some(TxRuleError::TooManyOutputs(16, 15))
    );
    assert_eq!(
        submitted.consensus_error,
        Some(TxRuleError::TooManyOutputs(16, 10))
    );

    let mut tx = valid_tx.clone();
    tx.outputs[0].script_public_key =
        ScriptPublicKey::from_vec(0, vec![0u8; params.max_script_public_key_len + 1]);
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TooBigScriptPublicKey(0, 10_000));

    let mut tx = valid_tx.clone();
    tx.inputs.push(tx.inputs[0].clone());
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TxDuplicateInputs);

    let mut tx = valid_tx.clone();
    tx.gas = 1;
    assert_refused_in_isolation!(&params, &tx, TxRuleError::TxHasGas(_));

    let mut tx = valid_tx.clone();
    tx.payload = vec![0];
    assert_matches!(isolation::validate_tx_in_isolation(&params, &tx), Ok(()));

    let mut tx = valid_tx.clone();
    tx.version = 1;
    tx.inputs[0].compute_commit = ComputeCommit::SigopCount(1.into());
    assert_refused_in_isolation!(&params, &tx, TxRuleError::SigopCountInV1(0, 1));

    let mut tx = valid_tx.clone();
    tx.version = 0;
    tx.inputs[0].compute_commit = ComputeCommit::ComputeBudget(1.into());
    assert_refused_in_isolation!(&params, &tx, TxRuleError::ComputeBudgetInV0(0, 1));

    let mut tx = valid_tx.clone();
    tx.version = TX_VERSION_TOCCATA + 1;
    assert_refused_in_isolation!(&params, &tx, TxRuleError::UnknownTxVersion(2));

    // tx_validation_in_isolation.rs:411-415: the version bound of the pre-fork side.
    let mut tx = valid_tx;
    tx.version = TX_VERSION + 1;
    assert_matches!(
        header::validate_tx_in_header_context(&params, &tx, LockTimeArg::Finalized, 0),
        Err(TxRuleError::UnknownTxVersion(1))
    );
}

/// tx_validation_in_isolation.rs:418-500.
#[test]
fn check_transaction_subnetwork_shape() {
    fn sid(
        namespace: [u8; SUBNETWORK_NAMESPACE_LEN],
        tail: [u8; SUBNETWORK_ZERO_TAIL_LEN],
    ) -> SubnetworkId {
        let mut bytes = [0u8; SUBNETWORK_ID_SIZE];
        bytes[..SUBNETWORK_NAMESPACE_LEN].copy_from_slice(&namespace);
        bytes[SUBNETWORK_NAMESPACE_LEN..].copy_from_slice(&tail);
        SubnetworkId::from_bytes(bytes)
    }

    fn tx_with(subnetwork_id: SubnetworkId, version: u16) -> Transaction {
        // Minimal tx: one input + one output so only the subnetwork check is exercised here.
        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_slice(&[0u8; 32]),
                index: 0,
            },
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(0.into()),
        };
        let output = TransactionOutput {
            value: 1,
            script_public_key: ScriptPublicKey::from_vec(0, vec![0u8]),
            covenant: None,
        };
        Transaction::new(
            version,
            vec![input],
            vec![output],
            0,
            subnetwork_id,
            0,
            vec![],
        )
    }

    // Reserved IDs (19-byte zero suffix): native/coinbase only, allowed at any version.
    for version in [TX_VERSION, TX_VERSION_TOCCATA] {
        isolation::check_transaction_subnetwork(&tx_with(SUBNETWORK_ID_NATIVE, version)).unwrap();
        isolation::check_transaction_subnetwork(&tx_with(SUBNETWORK_ID_COINBASE, version)).unwrap();
    }

    // [x, 0x00 * 19] for any x other than native and coinbase: rejected at every version.
    for byte in [0x02u8, 0x07, 0xff] {
        let reserved_shape = SubnetworkId::from_byte(byte);
        for version in [TX_VERSION, TX_VERSION_TOCCATA] {
            assert_matches!(
                isolation::check_transaction_subnetwork(&tx_with(reserved_shape, version)),
                Err(TxRuleError::SubnetworksDisabled(_))
            );
        }
    }

    // User lane [namespace, 0x00 * 16] with a non-zero byte in bytes[1..4]: any first byte
    // is accepted in a version 1 transaction and none in a version 0 transaction.
    for namespace in [
        [0x11, 0x22, 0x33, 0x44],
        [0x00, 0x00, 0x00, 0x01],
        [0xde, 0xad, 0xbe, 0xef],
        [0x07, 0x01, 0, 0],
    ] {
        let lane = sid(namespace, [0; SUBNETWORK_ZERO_TAIL_LEN]);
        isolation::check_transaction_subnetwork(&tx_with(lane, TX_VERSION_TOCCATA)).unwrap();
        assert_matches!(
            isolation::check_transaction_subnetwork(&tx_with(lane, TX_VERSION)),
            Err(TxRuleError::SubnetworksDisabled(_))
        );
    }

    // Non-zero tail: rejected in a version 1 transaction too.
    let mut dirty_tail = [0u8; SUBNETWORK_ZERO_TAIL_LEN];
    dirty_tail[0] = 1;
    let tail_byte_set = sid([0x11, 0, 0, 0], dirty_tail);
    assert_matches!(
        isolation::check_transaction_subnetwork(&tx_with(tail_byte_set, TX_VERSION_TOCCATA)),
        Err(TxRuleError::SubnetworksDisabled(_))
    );
    let mut dirty_tail_last = [0u8; SUBNETWORK_ZERO_TAIL_LEN];
    *dirty_tail_last.last_mut().unwrap() = 0xff;
    let tail_last_set = sid([0, 0, 0, 1], dirty_tail_last);
    assert_matches!(
        isolation::check_transaction_subnetwork(&tx_with(tail_last_set, TX_VERSION_TOCCATA)),
        Err(TxRuleError::SubnetworksDisabled(_))
    );

    let user_lane = sid([0, 0, 0, 1], [0; SUBNETWORK_ZERO_TAIL_LEN]);
    let reserved_shape = SubnetworkId::from_byte(2);
    for (subnetwork_id, version, gas_allowed) in [
        (SUBNETWORK_ID_NATIVE, TX_VERSION_TOCCATA, false),
        (SUBNETWORK_ID_COINBASE, TX_VERSION_TOCCATA, false),
        (reserved_shape, TX_VERSION_TOCCATA, false),
        (user_lane, TX_VERSION, false),
        (user_lane, TX_VERSION_TOCCATA, true),
    ] {
        let mut tx = tx_with(subnetwork_id, version);
        tx.gas = 1;
        assert_matches!(
            (isolation::check_gas(&tx), gas_allowed),
            (Ok(()), true) | (Err(TxRuleError::TxHasGas(_)), false)
        );
    }
}

/// The limit a signature script is held to in isolation is the larger fork value only
/// while the fork is scheduled: `ForkedParam::upper_bound` answers with the pre-fork
/// value for a fork that never activates and with the post-fork value for one that
/// always has (rusty-kaspa a41a333 consensus/core/src/config/params.rs:162-173). The port
/// reads the limit through the same call, so it follows.
#[test]
fn the_isolation_limit_of_a_signature_script_follows_the_fork_schedule() {
    let with_script_len = |len: usize| {
        let mut tx = valid_tx();
        tx.inputs[0].signature_script = vec![0; len];
        tx
    };

    let mut never = test_params();
    never.toccata_activation = ForkActivation::never();
    assert_eq!(
        isolation::validate_tx_in_isolation(&never, &with_script_len(10_000)),
        Ok(())
    );
    assert_eq!(
        isolation::validate_tx_in_isolation(&never, &with_script_len(10_001)),
        Err(TxRuleError::TooBigSignatureScript(0, 10_000))
    );

    let mut always = test_params();
    always.toccata_activation = ForkActivation::always();
    assert_eq!(
        isolation::validate_tx_in_isolation(&always, &with_script_len(250_000)),
        Ok(())
    );
    assert_eq!(
        isolation::validate_tx_in_isolation(&always, &with_script_len(250_001)),
        Err(TxRuleError::TooBigSignatureScript(0, 250_000))
    );

    let scheduled = test_params();
    assert_eq!(
        isolation::validate_tx_in_isolation(&scheduled, &with_script_len(250_000)),
        Ok(())
    );
}

/// A coinbase transaction is never put through the UTXO-context rules by a node: the
/// virtual processor skips the first transaction of a block
/// (rusty-kaspa a41a333 consensus/src/pipeline/virtual_processor/utxo_validation.rs:326
/// and 348) and a coinbase in any other place is refused as a second coinbase
/// (consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:46-56). The gate
/// in block mode must therefore not answer for a coinbase with the amounts rule of
/// ordinary transactions: no `SpendTooHigh` for upstream's own valid coinbase.
#[test]
fn a_coinbase_in_a_block_is_not_judged_by_the_amounts_rule() {
    let params = test_params();
    let coinbase = valid_coinbase();
    let evaluation = gate::evaluate(&gate_at_zero(&params), &coinbase, &[], GateOptions::block());
    assert!(
        !matches!(
            evaluation.consensus_error,
            Some(TxRuleError::SpendTooHigh(_, _))
        ),
        "a node never compares the outputs of a coinbase with its (absent) inputs: {:?}",
        evaluation.verdict.first_refusal
    );
    // What the gate says instead: no consensus refusal, and no acceptance either. The
    // rules that remain for a coinbase are block rules it does not model.
    assert_eq!(evaluation.consensus_error, None);
    assert!(!evaluation.verdict.accepted);
    assert_eq!(evaluation.verdict.stage_reached, Stage::Harness);
    assert!(
        evaluation
            .verdict
            .harness_error
            .as_deref()
            .is_some_and(|reason| reason.contains("coinbase")),
        "{:?}",
        evaluation.verdict.harness_error
    );

    // Submitted to a mempool the same transaction does reach the amounts rule, as in a
    // node (consensus/src/pipeline/virtual_processor/utxo_validation.rs:442-490).
    let submitted = gate::evaluate(
        &gate_at_zero(&params),
        &coinbase,
        &[],
        GateOptions::submit(),
    );
    assert_eq!(
        submitted.consensus_error,
        Some(TxRuleError::SpendTooHigh(0x12a05f200, 0))
    );
}
