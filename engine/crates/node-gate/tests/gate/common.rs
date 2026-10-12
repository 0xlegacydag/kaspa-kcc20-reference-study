//! Shared builders. Everything is fixed: keys from seed bytes, outpoints from tag bytes,
//! coin ages relative to the gate's DAA score.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    hashing::sighash_type::{SIG_HASH_ALL, SigHashType},
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_hashes::Hash;
use node_gate::{
    GateOptions, GateParams, Mode, Stage,
    gate::{self, Evaluation},
    header, isolation, mass,
    policy::PolicyRule,
    utxo,
    wallet::{self, TestKey},
};

/// Sompi per KAS.
pub const KAS: u64 = 100_000_000;

/// How many DAA scores before "now" the test coins were created.
pub const COIN_AGE: u64 = 10_000;

/// Testnet-10, well after Toccata.
pub fn node() -> GateParams {
    GateParams::testnet10()
}

/// Testnet-10 one DAA score before Toccata activates.
pub fn node_before_toccata() -> GateParams {
    let gate = GateParams::testnet10();
    let activation = gate.params.toccata_activation.daa_score();
    gate.with_daa_score(activation - 1)
}

/// The outpoint `index` of a made-up transaction whose id is 32 copies of `tag`.
pub fn outpoint(tag: u8, index: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([tag; 32]), index)
}

/// An ordinary coin: not coinbase, no covenant id, `COIN_AGE` old.
pub fn coin(gate: &GateParams, amount: u64, script_public_key: ScriptPublicKey) -> UtxoEntry {
    UtxoEntry::new(amount, script_public_key, gate.pov_daa_score - COIN_AGE, false, None)
}

/// A version 1 input with an empty signature script and sequence 0.
pub fn input_v1(tag: u8, budget: u16) -> TransactionInput {
    TransactionInput::new_with_compute_budget(outpoint(tag, 0), vec![], 0, budget)
}

/// A version 0 input with an empty signature script and sequence 0.
pub fn input_v0(tag: u8, sig_op_count: u8) -> TransactionInput {
    TransactionInput::new(outpoint(tag, 0), vec![], 0, sig_op_count)
}

/// A version 1 transaction on the native subnetwork: no lock time, no gas, no payload.
pub fn tx_v1(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// A version 0 transaction on the native subnetwork: no lock time, no gas, no payload.
pub fn tx_v0(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// An output paying to the Schnorr key of `seed`.
pub fn pay(seed: u8, value: u64) -> TransactionOutput {
    TransactionOutput::new(value, TestKey::from_seed(seed).p2pk_script_public_key())
}

/// A transaction with the coins it spends.
#[derive(Clone)]
pub struct Spend {
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
}

impl Spend {
    pub fn new(tx: Transaction, entries: Vec<UtxoEntry>) -> Self {
        Self { tx, entries }
    }

    pub fn populated(&self) -> PopulatedTransaction<'_> {
        PopulatedTransaction::new(&self.tx, self.entries.clone())
    }

    /// Signs one pay-to-pubkey input with a Schnorr signature.
    pub fn sign_p2pk(&mut self, input: usize, key: &TestKey, hash_type: SigHashType) {
        let script = key.p2pk_signature_script(&self.populated(), input, hash_type);
        self.tx.inputs[input].signature_script = script;
    }

    /// Replaces the signature script of one input with a single push of `item`.
    pub fn set_signature_item(&mut self, input: usize, item: &[u8]) {
        self.tx.inputs[input].signature_script = wallet::push_data(item);
    }

    /// Writes the calculated storage mass into the transaction, as a wallet does before
    /// the transaction goes into a block.
    pub fn commit_storage_mass(&self, gate: &GateParams) {
        let storage_mass = mass::calculated_storage_mass(&gate.params, &self.tx, &self.entries)
            .expect("coins a node could hold")
            .expect("a computable storage mass");
        self.tx.set_storage_mass(storage_mass);
    }
}

/// The key that owns the coin of `plain_spend`.
pub const OWNER: u8 = 1;
/// The key the outputs of `plain_spend` pay to.
pub const RECEIVER: u8 = 2;
/// Fee of `plain_spend`, in sompi.
pub const PLAIN_FEE: u64 = 1_000_000;

/// One pay-to-pubkey coin of 10 KAS spent to one pay-to-pubkey output, fee 0.01 KAS,
/// version 1, compute budget 10, signed with SIGHASH_ALL. A node accepts it on submission.
pub fn plain_spend(gate: &GateParams) -> Spend {
    let owner = TestKey::from_seed(OWNER);
    let entries = vec![coin(gate, 10 * KAS, owner.p2pk_script_public_key())];
    let tx = tx_v1(vec![input_v1(0xa1, 10)], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]);
    let mut spend = Spend::new(tx, entries);
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    spend
}

/// The same spend as a version 0 transaction with a signature operation count of 1.
pub fn plain_spend_v0(gate: &GateParams) -> Spend {
    let owner = TestKey::from_seed(OWNER);
    let entries = vec![coin(gate, 10 * KAS, owner.p2pk_script_public_key())];
    let tx = tx_v0(vec![input_v0(0xa1, 1)], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]);
    let mut spend = Spend::new(tx, entries);
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    spend
}

/// A pay-to-script-hash coin of 10 KAS locked to `redeem_script`, spent to one
/// pay-to-pubkey output with fee 0.01 KAS. The signature script is `arguments` followed
/// by the push of the redeem script.
pub fn p2sh_spend(gate: &GateParams, redeem_script: &[u8], arguments: &[u8], budget: u16) -> Spend {
    let entries = vec![coin(gate, 10 * KAS, wallet::p2sh_script_public_key(redeem_script))];
    let mut input = input_v1(0xb1, budget);
    input.signature_script = wallet::p2sh_signature_script(arguments, redeem_script);
    Spend::new(tx_v1(vec![input], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]), entries)
}

/// A coin whose script public key is `script` itself (no hash wrapper), spent with the
/// signature script `signature_script`.
pub fn bare_spend(gate: &GateParams, script: &[u8], signature_script: &[u8], budget: u16) -> Spend {
    let entries = vec![coin(gate, 10 * KAS, ScriptPublicKey::from_vec(0, script.to_vec()))];
    let mut input = input_v1(0xc1, budget);
    input.signature_script = signature_script.to_vec();
    Spend::new(tx_v1(vec![input], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]), entries)
}

/// The consensus answer assembled from the one-function ports, the way a node chains
/// them. `gate::evaluate` walks the same rules step by step; the two must agree.
pub fn consensus_by_composites(gate: &GateParams, spend: &Spend, mode: Mode) -> Result<u64, TxRuleError> {
    let tx = &spend.tx;
    isolation::validate_tx_in_isolation(&gate.params, tx)?;
    let header_daa_score = match mode {
        Mode::Submit => gate.pov_daa_score,
        Mode::Block => gate.block_daa_score,
    };
    header::validate_tx_in_header_context_with_args(&gate.params, tx, header_daa_score, gate.past_median_time)?;
    if spend.entries.len() < tx.inputs.len() {
        return Err(TxRuleError::MissingTxOutpoints);
    }
    let flags = match mode {
        Mode::Submit => {
            let storage_mass =
                gate.mass_calculator().calc_contextual_masses(&spend.populated()).ok_or(TxRuleError::MassIncomputable)?.storage_mass;
            tx.set_storage_mass(storage_mass);
            utxo::TxValidationFlags::SkipMassCheck
        }
        Mode::Block => utxo::TxValidationFlags::Full,
    };
    utxo::validate_populated_transaction_and_get_fee(gate, &spend.populated(), flags)
}

/// Evaluates and checks that the step-by-step walk of `gate::evaluate` gives the consensus
/// answer of the chained ports. Only for transactions a node could be asked about and, in
/// block mode, within the block limits.
pub fn evaluate(gate: &GateParams, spend: &Spend, options: GateOptions) -> Evaluation {
    let evaluation = gate::evaluate(gate, &spend.tx, &spend.entries, options);
    assert_eq!(evaluation.verdict.harness_error, None);
    if evaluation.block_mass_error.is_none() {
        let by_composites = consensus_by_composites(gate, spend, options.mode);
        assert_eq!(evaluation.consensus_error.as_ref(), by_composites.as_ref().err(), "step-by-step walk and chained ports disagree");
        if let Ok(fee) = by_composites {
            assert_eq!(evaluation.verdict.fee, Some(fee));
        }
    }
    assert_mempool_answer_agrees_with_the_report(&evaluation);
    evaluation
}

/// The node's mempool answer is taken from the composed ports, which keep the upstream
/// order in their bodies; the rule-by-rule report walks the two rule lists. Wherever a
/// node gets to a group of mempool rules, the two must name the same first refusal.
pub fn assert_mempool_answer_agrees_with_the_report(evaluation: &Evaluation) {
    let Some(report) = evaluation.verdict.policy.as_ref() else {
        return;
    };
    let first_of = |rules: &[PolicyRule]| {
        report.refusals().find(|(rule, _)| rules.contains(rule)).map(|(rule, _)| gate::policy_rule_function(rule).to_string())
    };
    let answer = evaluation.verdict.first_refusal.as_ref();
    let answered_at = |stage: Stage| answer.filter(|refusal| refusal.stage == stage).map(|refusal| refusal.rule.clone());

    // The first group is applied once the masses are known.
    if evaluation.pre_mass_error.is_none() {
        assert_eq!(
            answered_at(Stage::MempoolBeforeConsensus),
            first_of(&PolicyRule::BEFORE_CONSENSUS),
            "before the consensus validation"
        );
    }
    // The second group is applied once the first group and the consensus validation passed.
    if evaluation.verdict.consensus_accepted && first_of(&PolicyRule::BEFORE_CONSENSUS).is_none() {
        assert_eq!(
            answered_at(Stage::MempoolAfterConsensus),
            first_of(&PolicyRule::AFTER_CONSENSUS),
            "after the consensus validation"
        );
    }
}

/// Submit mode with the default options.
pub fn submit(gate: &GateParams, spend: &Spend) -> Evaluation {
    evaluate(gate, spend, GateOptions::submit())
}

/// Block mode with the default options.
pub fn in_block(gate: &GateParams, spend: &Spend) -> Evaluation {
    evaluate(gate, spend, GateOptions::block())
}
