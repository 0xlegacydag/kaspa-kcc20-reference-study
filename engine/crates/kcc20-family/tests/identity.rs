//! The published artifact is the pinned one, and the family reads it as published.

use argent::codec::{ArtifactValue, encode_hex};
use kcc20_family::refdata::{self, PINNED_APP, PINNED_ARTIFACT_ID};
use kcc20_family::sourcemap::compile_source;
use kcc20_family::states::{Kcc20State, PublicMintState, State, TokenSeedState};
use kcc20_family::{Contract, Entry, EntryRole, Family, keys, raw};

/// Size, state span and template hash of every contract as published
/// (fixtures/public-mint/artifact.json of kcc20-reference c8a0871).
const PUBLISHED: [(Contract, usize, usize, usize, &str); 3] = [
    (
        Contract::Kcc20,
        4031,
        1,
        145,
        "9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7",
    ),
    (
        Contract::PublicMint,
        2019,
        1,
        150,
        "14b0f06bc176b78c94f19292e409c622636f31dae6bb31ff3d4d3308a6053b49",
    ),
    (
        Contract::TokenSeed,
        1355,
        1,
        132,
        "f79a3fccf6f87d7076662410a17e54d1531889d9b60f630f9fbb8465a384e62d",
    ),
];

/// Dispatch tag of every entry as published.
const PUBLISHED_TAGS: [(Entry, &str); 11] = [
    (Entry::Transfer, "79c71c23"),
    (Entry::TransferDelegator, "fd3ef14a"),
    (Entry::Mint, "0fe04b09"),
    (Entry::MintSplit, "52f03341"),
    (Entry::MintReclaim, "35eecca6"),
    (Entry::MintReclaimInto, "6f52c1a9"),
    (Entry::MintReclaimDelegator, "ebe6a147"),
    (Entry::SeedCreate, "d1f8dfa0"),
    (Entry::SeedSplit, "5dc68e50"),
    (Entry::SeedReclaim, "f56af4df"),
    (Entry::SeedReclaimDelegator, "ebe6a147"),
];

fn sample_states() -> [State; 3] {
    [
        Kcc20State::new(keys::x_only(keys::ALICE), 100).into(),
        PublicMintState::new(keys::x_only(keys::ALICE), 25, 10).into(),
        TokenSeedState::new(keys::x_only(keys::ALICE)).into(),
    ]
}

#[test]
fn the_published_artifact_is_the_pinned_one() {
    let artifact = refdata::load_pinned_artifact()
        .expect("the published artifact loads and passes Argent's consistency check");
    assert_eq!(artifact.id, PINNED_ARTIFACT_ID);
    assert_eq!(
        artifact.id,
        "b48c90c8e287d227821ac40f0875a753e329e1ab3c8fdfa1477f55419cfa26ab"
    );
    assert_eq!(artifact.app, PINNED_APP);
    // The id is not just a stored string: Argent recomputes it from the content.
    assert_eq!(
        artifact.computed_id_hex().expect("the id can be computed"),
        PINNED_ARTIFACT_ID
    );
    assert!(
        artifact.dependencies.is_empty(),
        "the application links no other application"
    );
}

#[test]
fn a_changed_artifact_fails_the_consistency_check() {
    // One byte of the KCC20 bytecode changed, everything else as published: the template hash
    // no longer matches, so the file cannot pass for the pinned artifact.
    let mut artifact = refdata::load_pinned_artifact().expect("artifact");
    let compiled = &mut artifact
        .sil_abi
        .contracts
        .get_mut("KCC20")
        .expect("KCC20")
        .compiled;
    let last = compiled.bytecode.len() - 1;
    compiled.bytecode[last] ^= 0x01;
    assert!(artifact.check_consistency().is_err());
    assert!(Family::from_artifact(artifact).is_err());
}

#[test]
fn contracts_have_the_published_sizes_spans_and_template_hashes() {
    let family = Family::pinned();
    for (contract, size, span_offset, span_len, hash) in PUBLISHED {
        assert_eq!(family.bytecode(contract).len(), size, "{contract} size");
        assert_eq!(
            family.state_span(contract),
            span_offset..span_offset + span_len,
            "{contract} state span"
        );
        assert_eq!(
            encode_hex(&family.template_hash(contract)),
            hash,
            "{contract} template hash"
        );
        assert_eq!(
            family.prefix(contract),
            [0x6b],
            "{contract} prefix is the single opcode OpToAltStack"
        );
        assert_eq!(
            family.suffix(contract).len(),
            size - span_offset - span_len,
            "{contract} suffix length"
        );
        // In the template the state is zero-filled: only push opcodes and zero bytes.
        let state = &family.bytecode(contract)[family.state_span(contract)];
        let pushes = raw::split_pushes(state).expect("the state span is a sequence of pushes");
        assert!(
            pushes
                .iter()
                .all(|push| push[1..].iter().all(|byte| *byte == 0)),
            "{contract} template state is zero-filled"
        );
    }
}

#[test]
fn template_hashes_follow_the_documented_formula() {
    // BLAKE3 over: length of the prefix as 8 little-endian bytes, the prefix, length of the
    // suffix as 8 little-endian bytes, the suffix. Spelled out step by step here, independent
    // of the function the family uses.
    let family = Family::pinned();
    for contract in Contract::ALL {
        let prefix = family.prefix(contract);
        let suffix = family.suffix(contract);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(prefix.len() as u64).to_le_bytes());
        hasher.update(prefix);
        hasher.update(&(suffix.len() as u64).to_le_bytes());
        hasher.update(suffix);
        assert_eq!(
            *hasher.finalize().as_bytes(),
            family.template_hash(contract),
            "{contract}"
        );
    }
}

#[test]
fn entries_have_the_published_dispatch_tags_and_roles() {
    let family = Family::pinned();
    for (entry, tag) in PUBLISHED_TAGS {
        assert_eq!(encode_hex(&family.dispatch_tag(entry)), tag, "{entry}");
    }
    assert_eq!(Entry::ALL.len(), 11);
    let delegates: Vec<Entry> = Entry::ALL
        .into_iter()
        .filter(|entry| entry.role() == EntryRole::Delegate)
        .collect();
    assert_eq!(
        delegates,
        [
            Entry::TransferDelegator,
            Entry::MintReclaimDelegator,
            Entry::SeedReclaimDelegator
        ]
    );
    for entry in Entry::ALL {
        assert_eq!(
            Entry::from_name(entry.contract(), entry.name()),
            Some(entry)
        );
    }
}

#[test]
fn the_pinned_sources_compile_to_the_pinned_bytecode() {
    // The generated SilverScript sources of the reference, compiled again by the pinned
    // compiler with zero-valued constructor arguments, give the bytecode of the artifact byte
    // for byte, with debug information on and off.
    let family = Family::pinned();
    for contract in Contract::ALL {
        let source = refdata::load_sil_source(contract).expect("the generated source is readable");
        for record_debug_info in [false, true] {
            let compiled =
                compile_source(contract, &source, record_debug_info).expect("the source compiles");
            assert_eq!(
                compiled.bytecode.len(),
                family.bytecode(contract).len(),
                "{contract} length (debug {record_debug_info})"
            );
            assert!(
                compiled.bytecode == family.bytecode(contract),
                "{contract} bytes (debug {record_debug_info})"
            );
            assert_eq!(
                compiled.steps.is_empty(),
                !record_debug_info,
                "{contract}: steps are recorded only on request"
            );
        }
    }
}

#[test]
fn states_are_encoded_into_the_published_layout() {
    let family = Family::pinned();
    let kcc20_hash = family.template_hash(Contract::Kcc20);
    for state in sample_states() {
        let contract = state.contract();
        let bytes = family.state_bytes(&state).expect("the state encodes");
        assert_eq!(
            bytes.len(),
            family.state_span(contract).len(),
            "{contract}: every field has a fixed width"
        );
        // Every state starts with the push of the KCC20 template hash.
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1..33], kcc20_hash, "{contract}: gen__kcc20_template");
        let redeem = family.redeem_script(&state).expect("redeem script");
        assert_eq!(redeem.len(), family.bytecode(contract).len());
        assert_eq!(redeem[..1], *family.prefix(contract));
        assert_eq!(redeem[family.state_span(contract)], bytes[..]);
        assert_eq!(
            redeem[family.state_span(contract).end..],
            *family.suffix(contract)
        );
        // The script public key is pay-to-script-hash of the redeem script: aa 20 <hash> 87.
        let script_public_key = family.script_public_key(&state).expect("script public key");
        assert_eq!(script_public_key.version(), 0);
        let script = script_public_key.script();
        assert_eq!(script.len(), 35);
        assert_eq!((script[0], script[1], script[34]), (0xaa, 0x20, 0x87));
        let hash = blake2b_simd::Params::new().hash_length(32).hash(&redeem);
        assert_eq!(script[2..34], *hash.as_bytes());
    }
    // PublicMint and TokenSeed carry their own template hash as the second field.
    for (state, contract) in [
        (&sample_states()[1], Contract::PublicMint),
        (&sample_states()[2], Contract::TokenSeed),
    ] {
        let bytes = family.state_bytes(state).expect("the state encodes");
        assert_eq!(bytes[33], 0x20);
        assert_eq!(
            bytes[34..66],
            family.template_hash(contract),
            "{contract}: its own template hash"
        );
    }
}

#[test]
fn hidden_arguments_are_the_kcc20_prefix_and_suffix_of_mint_and_create_only() {
    let family = Family::pinned();
    for entry in Entry::ALL {
        let hidden = family.hidden_args(entry).expect("hidden arguments resolve");
        if matches!(entry, Entry::Mint | Entry::SeedCreate) {
            assert_eq!(
                hidden,
                [
                    ArtifactValue::Bytes(family.prefix(Contract::Kcc20).to_vec()),
                    ArtifactValue::Bytes(family.suffix(Contract::Kcc20).to_vec())
                ],
                "{entry}"
            );
        } else {
            assert!(hidden.is_empty(), "{entry} has no hidden arguments");
        }
    }
}

#[test]
fn a_call_is_argument_pushes_then_the_tag_then_the_redeem_script() {
    let family = Family::pinned();
    let minter: State = PublicMintState::new(keys::x_only(keys::ALICE), 18, 10).into();
    // An entry without arguments: the call is the tag push alone.
    assert_eq!(
        family
            .call_bytes(Entry::MintReclaimInto, &[])
            .expect("call"),
        [0x04, 0x6f, 0x52, 0xc1, 0xa9]
    );
    let script = family
        .signature_script(Entry::MintReclaimInto, &[], &minter)
        .expect("signature script");
    let redeem = family.redeem_script(&minter).expect("redeem script");
    // 2019 bytes = 0x07e3: OpPushData2 with a little-endian length.
    assert_eq!(
        script[..8],
        [0x04, 0x6f, 0x52, 0xc1, 0xa9, 0x4d, 0xe3, 0x07]
    );
    assert_eq!(script[8..], redeem[..]);

    // mint: six pushes of the recipient state, the two hidden arguments, the tag.
    let recipient = Kcc20State::new(keys::x_only(keys::ALICE), 10);
    let parts = family
        .call_parts(
            Entry::Mint,
            &[kcc20_family::states::kcc20_state_value(&recipient)],
            &redeem,
        )
        .expect("call parts");
    assert_eq!(parts.arguments.len(), 8);
    assert_eq!(
        parts.arguments[0],
        [0x5a],
        "amount 10 is the small-integer opcode Op10"
    );
    assert_eq!(parts.arguments[1][0], 0x20);
    assert_eq!(parts.arguments[1][1..], keys::x_only(keys::ALICE));
    assert_eq!(
        parts.arguments[2],
        [0x01, 0x00],
        "owner_scheme 0 is a one-byte push of 00"
    );
    assert_eq!(
        parts.arguments[3],
        [0x01, 0x00],
        "borrow_scheme 0 is a one-byte push of 00"
    );
    assert_eq!(parts.arguments[6], [0x01, 0x6b], "the KCC20 prefix");
    assert_eq!(
        parts.arguments[7][..3],
        [0x4d, 0x2d, 0x0f],
        "the 3885-byte KCC20 suffix"
    );
    assert_eq!(parts.arguments[7][3..], *family.suffix(Contract::Kcc20));
    assert_eq!(parts.tag, [0x04, 0x0f, 0xe0, 0x4b, 0x09]);
    assert_eq!(parts.redeem[..3], [0x4d, 0xe3, 0x07]);
    // The parts joined are exactly what the one-step function gives.
    assert_eq!(
        parts.signature_script(),
        family
            .signature_script(
                Entry::Mint,
                &[kcc20_family::states::kcc20_state_value(&recipient)],
                &minter
            )
            .expect("signature script")
    );
}

#[test]
fn the_codec_refuses_what_only_raw_bytes_can_say() {
    // A signature argument must be 65 bytes for the codec; an empty one has to be hand-made.
    let family = Family::pinned();
    assert!(
        family
            .call_bytes(Entry::MintReclaim, &[ArtifactValue::Bytes(Vec::new())])
            .is_err()
    );
    assert!(
        family.call_bytes(Entry::MintReclaim, &[]).is_err(),
        "a missing argument is refused too"
    );
    assert!(
        family
            .call_bytes(Entry::MintReclaim, &[ArtifactValue::Bytes(vec![0; 65])])
            .is_ok()
    );
}

#[test]
fn a_replaced_bytecode_reaches_the_others_through_hashes_only() {
    let family = Family::pinned();
    let [token, minter, seed] = sample_states();

    // The same bytes again: same hash, nothing changes.
    let same = family
        .with_bytecode(Contract::Kcc20, family.bytecode(Contract::Kcc20).to_vec())
        .expect("replace");
    assert_eq!(
        same.template_hash(Contract::Kcc20),
        family.template_hash(Contract::Kcc20)
    );
    assert_eq!(
        same.redeem_script(&token).expect("redeem"),
        family.redeem_script(&token).expect("redeem")
    );
    assert_eq!(same.replaced(), [Contract::Kcc20]);
    assert!(family.replaced().is_empty());
    assert!(
        same.artifact().is_none(),
        "a patched family is not an Argent artifact any more"
    );
    assert!(family.artifact().is_some());

    // One byte of KCC20 changed (the last OpEndIf becomes OpNop): KCC20 gets a new hash, and
    // every coin of the family changes, because every state holds the KCC20 hash.
    let mut patched = family.bytecode(Contract::Kcc20).to_vec();
    let last = patched.len() - 1;
    assert_eq!(patched[last], 0x68);
    patched[last] = 0x61;
    let changed = family
        .with_bytecode(Contract::Kcc20, patched.clone())
        .expect("replace");
    assert_ne!(
        changed.template_hash(Contract::Kcc20),
        family.template_hash(Contract::Kcc20)
    );
    assert_eq!(changed.bytecode(Contract::Kcc20), patched);
    assert_eq!(
        changed.state_span(Contract::Kcc20),
        family.state_span(Contract::Kcc20),
        "the state span is kept"
    );
    for contract in [Contract::PublicMint, Contract::TokenSeed] {
        assert_eq!(
            changed.bytecode(contract),
            family.bytecode(contract),
            "{contract} bytecode is not recompiled"
        );
        assert_eq!(
            changed.template_hash(contract),
            family.template_hash(contract),
            "{contract} keeps its own hash"
        );
    }
    for state in [&token, &minter, &seed] {
        let before = family.state_bytes(state).expect("state");
        let after = changed.state_bytes(state).expect("state");
        assert_eq!(
            after[1..33],
            changed.template_hash(Contract::Kcc20),
            "the state carries the new KCC20 hash"
        );
        assert_eq!(after[33..], before[33..], "the other fields are as before");
        assert_ne!(
            changed.script_public_key(state).expect("spk"),
            family.script_public_key(state).expect("spk")
        );
    }
    // The hidden suffix argument of mint and create is the new KCC20 suffix.
    for entry in [Entry::Mint, Entry::SeedCreate] {
        let hidden = changed.hidden_args(entry).expect("hidden arguments");
        assert_eq!(
            hidden[1],
            ArtifactValue::Bytes(patched[146..].to_vec()),
            "{entry}"
        );
    }

    // One byte of PublicMint changed: only PublicMint coins change.
    let mut patched = family.bytecode(Contract::PublicMint).to_vec();
    let last = patched.len() - 1;
    patched[last] = 0x61;
    let changed = family
        .with_bytecode(Contract::PublicMint, patched)
        .expect("replace");
    assert_eq!(
        changed.redeem_script(&token).expect("redeem"),
        family.redeem_script(&token).expect("redeem")
    );
    assert_eq!(
        changed.redeem_script(&seed).expect("redeem"),
        family.redeem_script(&seed).expect("redeem")
    );
    let before = family.state_bytes(&minter).expect("state");
    let after = changed.state_bytes(&minter).expect("state");
    assert_eq!(after[..33], before[..33], "the KCC20 hash is as before");
    assert_eq!(after[34..66], changed.template_hash(Contract::PublicMint));
    assert_ne!(after[34..66], before[34..66]);

    // A replacement too short to hold the state span is refused.
    assert!(
        family
            .with_bytecode(Contract::TokenSeed, vec![0x6b; 100])
            .is_err()
    );
}

#[test]
fn hand_made_pushes_have_the_chosen_form() {
    use kcc20_family::raw::PushForm;

    let tag = [0x79, 0xc7, 0x1c, 0x23];
    assert_eq!(
        raw::push(&tag).expect("push"),
        [0x04, 0x79, 0xc7, 0x1c, 0x23]
    );
    assert_eq!(
        raw::push_as(PushForm::Direct, &tag),
        Some(vec![0x04, 0x79, 0xc7, 0x1c, 0x23])
    );
    assert_eq!(
        raw::push_as(PushForm::PushData1, &tag),
        Some(vec![0x4c, 0x04, 0x79, 0xc7, 0x1c, 0x23])
    );
    assert_eq!(
        raw::push_as(PushForm::PushData2, &tag),
        Some(vec![0x4d, 0x04, 0x00, 0x79, 0xc7, 0x1c, 0x23])
    );
    assert_eq!(
        raw::push_as(PushForm::PushData4, &tag),
        Some(vec![0x4e, 0x04, 0x00, 0x00, 0x00, 0x79, 0xc7, 0x1c, 0x23])
    );
    // A form that cannot hold the length is refused instead of being written wrongly.
    assert_eq!(raw::push_as(PushForm::Direct, &[0u8; 76]), None);
    assert_eq!(raw::push_as(PushForm::Direct, &[]), None);
    assert_eq!(raw::push_as(PushForm::PushData1, &[0u8; 256]), None);

    // The three forms the codec uses.
    assert_eq!(raw::push(&[]).expect("push"), [0x00]);
    assert_eq!(
        raw::push(&[0x01]).expect("push"),
        [0x51],
        "a canonical push of 01 is Op1"
    );
    assert_eq!(
        raw::push_explicit(&[0x01]).expect("push"),
        [0x01, 0x01],
        "an explicit push keeps its length byte"
    );
    assert_eq!(raw::push_number(0).expect("push"), [0x00]);
    assert_eq!(raw::push_number(10).expect("push"), [0x5a]);
    assert_eq!(raw::push_number(-1).expect("push"), [0x4f]);
    assert_eq!(raw::push_number(17).expect("push"), [0x01, 0x11]);
    assert_eq!(raw::push_number(128).expect("push"), [0x02, 0x80, 0x00]);

    // A script is cut into the pushes it was made of.
    let script = [
        raw::push_number(17).expect("push"),
        raw::push(&tag).expect("push"),
        vec![0x00],
    ]
    .concat();
    let pushes = raw::split_pushes(&script).expect("the script parses");
    assert_eq!(
        pushes,
        [
            vec![0x01, 0x11],
            vec![0x04, 0x79, 0xc7, 0x1c, 0x23],
            vec![0x00]
        ]
    );
    assert_eq!(raw::count_opcodes(&script), Some(3));
    // A script that ends inside a push does not parse.
    assert!(raw::split_pushes(&[0x04, 0x79]).is_err());
    assert_eq!(raw::count_opcodes(&[0x04, 0x79]), None);
}
