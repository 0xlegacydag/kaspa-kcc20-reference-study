//! The KCC-20 conformance vectors the reference ships (`fixtures/kcc20/conformance.json`):
//! state encoding, argument encoding of `transfer`, dispatch tags, witness layouts, key hashes
//! and the hash chain.
//!
//! No engine runs here: bytes are compared with bytes.

use argent::codec::{decode_hex, encode_hex};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::MutableTransaction;
use kcc20_family::keys::SigningContext;
use kcc20_family::states::{Kcc20State, State, kcc20_states_value};
use kcc20_family::{Arg, Entry, EntryRole, Family, Profile, raw, refdata, shapes, witness};
use serde_json::Value;

/// The whole file of vectors, read from the reference checkout.
fn conformance() -> Value {
    refdata::load_conformance_vectors().expect("the conformance vectors are readable")
}

/// Typed reads of one JSON value of the vectors. A value of another kind stops the test and
/// is shown in the message. Every byte string of the file is written as hex.
trait VectorValue {
    /// The elements of an array.
    fn items(&self) -> &[Value];
    /// A string.
    fn text(&self) -> &str;
    /// A number that is not negative.
    fn number(&self) -> u64;
    /// The bytes of a hex string.
    fn hex(&self) -> Vec<u8>;
    /// The bytes of a hex string that holds exactly `N` bytes.
    fn hex_exact<const N: usize>(&self) -> [u8; N];
    /// The byte of a hex string that holds exactly one byte.
    fn hex_byte(&self) -> u8;
}

impl VectorValue for Value {
    fn items(&self) -> &[Value] {
        self.as_array()
            .map(Vec::as_slice)
            .unwrap_or_else(|| panic!("not an array: {self}"))
    }

    fn text(&self) -> &str {
        self.as_str()
            .unwrap_or_else(|| panic!("not a string: {self}"))
    }

    fn number(&self) -> u64 {
        self.as_u64()
            .unwrap_or_else(|| panic!("not a number from 0 up: {self}"))
    }

    fn hex(&self) -> Vec<u8> {
        decode_hex(self.text()).unwrap_or_else(|error| panic!("not hex: {self}: {error}"))
    }

    fn hex_exact<const N: usize>(&self) -> [u8; N] {
        let decoded = self.hex();
        <[u8; N]>::try_from(decoded.as_slice())
            .unwrap_or_else(|_| panic!("{} bytes where {N} are expected: {self}", decoded.len()))
    }

    fn hex_byte(&self) -> u8 {
        let [only] = self.hex_exact::<1>();
        only
    }
}

/// A `KCC20State` record of the vectors as a typed state.
fn kcc20_state(record: &Value) -> Kcc20State {
    let amount = record["amount"]
        .as_i64()
        .unwrap_or_else(|| panic!("not an integer amount: {}", record["amount"]));
    let owner: [u8; 32] = record["owner_hex"].hex_exact();
    Kcc20State::new(owner, amount)
        .with_owner(record["owner_scheme_hex"].hex_byte(), owner)
        .with_borrow(
            record["borrow_scheme_hex"].hex_byte(),
            record["borrow_guard_hex"].hex_exact(),
        )
        .with_extension(record["extension_commitment_hex"].hex_exact())
}

#[test]
fn the_vectors_are_the_format_this_test_was_written_for() {
    let file = conformance();
    assert_eq!(file["kcc"], 20);
    assert_eq!(file["format_version"], 1);
}

#[test]
fn state_encoding_equals_the_vector() {
    let file = conformance();
    let family = Family::pinned();
    let case = &file["state_encoding"];
    let encoded = family
        .state_bytes(&State::Kcc20(kcc20_state(&case["state"])))
        .expect("the state encodes");

    // The physical state is the compiler-owned template field followed by the six fields of
    // the specification: 33 + 112 bytes.
    let (template_push, authored) = encoded.split_at(33);
    assert_eq!(template_push[0], 0x20);
    assert_eq!(
        template_push[1..],
        family.template_hash(kcc20_family::Contract::Kcc20)
    );
    assert_eq!(
        authored.len() as u64,
        file["state_record"]["encoded_state_length"].number()
    );
    assert_eq!(encode_hex(authored), case["encoded_hex"].text());

    // Field by field, in the order of the specification.
    let pushes = raw::split_pushes(&encoded).expect("a state is a sequence of pushes");
    let fields = case["encoded_fields_hex"].items();
    assert_eq!(pushes.len(), fields.len() + 1);
    for (push, field) in pushes[1..].iter().zip(fields) {
        assert_eq!(encode_hex(push), field.text());
    }
}

#[test]
fn transfer_argument_encoding_equals_the_vector() {
    let file = conformance();
    let family = Family::pinned();
    let case = &file["transfer_arguments"];
    let states: Vec<Kcc20State> = case["next_states"]
        .items()
        .iter()
        .map(kcc20_state)
        .collect();
    let witness = case["witness_hex"].hex();
    let columns = case["grouped_field_pushes_hex"].items();

    // The whole call of the vector: the column pushes, the witness push, the tag push.
    let expected: Vec<u8> = columns
        .iter()
        .chain([&case["witness_push_hex"], &case["dispatch_tag_push_hex"]])
        .flat_map(|value| value.hex())
        .collect();

    // Through the family, from codec values.
    let call = family
        .call_bytes(
            Entry::Transfer,
            &[kcc20_states_value(&states), witness.clone().into()],
        )
        .expect("the call encodes");
    assert_eq!(encode_hex(&call), encode_hex(&expected));

    // Split into parts: six column pushes, the witness push, the tag push.
    let parts = family
        .call_parts(
            Entry::Transfer,
            &[kcc20_states_value(&states), witness.clone().into()],
            &[0x51],
        )
        .expect("call parts");
    assert_eq!(parts.arguments.len(), columns.len() + 1);
    for (part, column) in parts.arguments.iter().zip(columns) {
        assert_eq!(encode_hex(part), column.text());
    }
    assert_eq!(
        encode_hex(&parts.arguments[6]),
        case["witness_push_hex"].text()
    );
    assert_eq!(encode_hex(&parts.tag), case["dispatch_tag_push_hex"].text());
    assert_eq!(parts.call_bytes(), expected);

    // Through a scenario, from typed arguments: the same bytes land in the signature script.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 2);
    let input = scenario.contract_input_mut(0);
    *input.declared_states_mut() = states;
    *input.witness_mut() = witness.clone().into();
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(
        assembled.tx.inputs[0].signature_script[..expected.len()],
        expected[..]
    );

    // The raw tools write the same pushes by hand.
    assert_eq!(
        raw::push(&witness).expect("push"),
        case["witness_push_hex"].hex()
    );
    assert_eq!(
        raw::push(&family.dispatch_tag(Entry::Transfer)).expect("push"),
        case["dispatch_tag_push_hex"].hex()
    );
}

#[test]
fn dispatch_tags_equal_the_vectors() {
    let file = conformance();
    let family = Family::pinned();
    for row in file["dispatch"].items() {
        let entry_name = row["entrypoint"].text();
        let entry = Entry::from_name(kcc20_family::Contract::Kcc20, entry_name)
            .unwrap_or_else(|| panic!("`{entry_name}` is not an entry of KCC20"));
        let tag = family.dispatch_tag(entry);
        assert_eq!(
            encode_hex(&tag),
            row["dispatch_tag_hex"].text(),
            "{entry_name}"
        );
        // The tag is the first four bytes of BLAKE3 over the function signature.
        let hashed = blake3::hash(row["function_signature"].text().as_bytes());
        assert_eq!(hashed.as_bytes()[..4], tag, "{entry_name}");
    }
}

#[test]
fn witness_layouts_have_the_lengths_of_the_vectors() {
    let file = conformance();
    let family = Family::pinned();

    // Owner schemes, leader role: the witness of the honest shape has the vector's length and
    // starts with the same path byte.
    for row in file["owner_witness"].items() {
        let scheme = row["owner_scheme_hex"].hex_byte();
        let mut scenario =
            shapes::transfer_with_owner_scheme(&Profile::Script, EntryRole::Leader, scheme);
        let assembled = scenario.assemble(family).expect("the shape assembles");
        let unsigned =
            MutableTransaction::with_entries(assembled.tx.clone(), assembled.utxos.clone());
        let witness = scenario
            .contract_input_mut(0)
            .witness_mut()
            .resolve(&SigningContext {
                tx: &unsigned,
                input_index: 0,
            });
        let expected = row["witness_hex"].hex();
        assert_eq!(
            witness.len() as u64,
            row["length"].number(),
            "owner scheme {scheme:#04x}"
        );
        assert_eq!(witness.len(), expected.len());
        assert_eq!(
            witness[0], expected[0],
            "owner scheme {scheme:#04x}: path byte"
        );
        // A delegate gives the same witness without the path byte.
        let delegate =
            shapes::transfer_with_owner_scheme(&Profile::Script, EntryRole::Delegate, scheme);
        let mut delegate_for_witness = delegate.clone();
        let assembled = delegate.assemble(family).expect("the shape assembles");
        let unsigned =
            MutableTransaction::with_entries(assembled.tx.clone(), assembled.utxos.clone());
        let delegate_witness = delegate_for_witness
            .contract_input_mut(1)
            .witness_mut()
            .resolve(&SigningContext {
                tx: &unsigned,
                input_index: 1,
            });
        assert_eq!(
            delegate_witness.len(),
            expected.len() - 1,
            "owner scheme {scheme:#04x}: delegate witness"
        );
    }

    // Borrow schemes.
    let unsigned = {
        let assembled = shapes::transfer(&Profile::Script, 1, 1)
            .assemble(family)
            .expect("the shape assembles");
        MutableTransaction::with_entries(assembled.tx.clone(), assembled.utxos.clone())
    };
    let ctx = SigningContext {
        tx: &unsigned,
        input_index: 0,
    };
    for row in file["borrow_witness"].items() {
        let scheme = row["borrow_scheme_hex"].hex_byte();
        let witness = match scheme {
            0x01 => witness::borrow_threshold(),
            0x02 => witness::borrow_signature(kcc20_family::keys::CAROL, SIG_HASH_ALL),
            0x03 => witness::borrow_hash_chain(
                shapes::CHAIN_NEXT_GUARD,
                kcc20_family::keys::CAROL,
                SIG_HASH_ALL,
            ),
            other => panic!("unexpected borrow scheme {other:#04x} in the vectors"),
        }
        .resolve(&ctx);
        let expected = row["witness_hex"].hex();
        assert_eq!(
            witness.len() as u64,
            row["length"].number(),
            "borrow scheme {scheme:#04x}"
        );
        assert_eq!(witness.len(), expected.len());
        assert_eq!(
            witness[0], expected[0],
            "borrow scheme {scheme:#04x}: path byte"
        );
    }
}

#[test]
fn key_hashes_and_the_hash_chain_equal_the_vectors() {
    let file = conformance();
    // Key hashes: plain BLAKE3 of the public key that sits between the path byte and the
    // 65-byte signature of the vector's witness.
    let mut checked = 0;
    for row in file["owner_witness"].items() {
        let Some(key_hash) = row.get("p2pkh_hash_hex") else {
            continue;
        };
        let witness = row["witness_hex"].hex();
        let public_key = &witness[1..witness.len() - 65];
        assert_eq!(
            encode_hex(&witness::public_key_hash(public_key)),
            key_hash.text()
        );
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "the vectors hold one Schnorr and one ECDSA key hash"
    );

    // Hash chain: x_i = BLAKE3(x_(i-1), key_i); the last link is the initial guard.
    let chain = &file["hash_chain"];
    let mut guard: [u8; 32] = chain["x_0_hex"].hex_exact();
    for link in chain["links"].items() {
        guard = witness::chain_guard_for_key(&guard, &link["pubkey_hex"].hex_exact());
        assert_eq!(
            encode_hex(&guard),
            link["x_hex"].text(),
            "link {}",
            link["i"]
        );
    }
    assert_eq!(encode_hex(&guard), chain["initial_borrow_guard_hex"].text());
}

#[test]
fn typed_arguments_resolve_to_the_codec_values_of_the_vector() {
    // `Arg::States` is the typed form of the vector's next_states; it must resolve to the
    // same codec value the vector test above encodes.
    let file = conformance();
    let family = Family::pinned();
    let states: Vec<Kcc20State> = file["transfer_arguments"]["next_states"]
        .items()
        .iter()
        .map(kcc20_state)
        .collect();
    let assembled = shapes::transfer(&Profile::Script, 1, 1)
        .assemble(family)
        .expect("the shape assembles");
    let unsigned = MutableTransaction::with_entries(assembled.tx.clone(), assembled.utxos.clone());
    let ctx = SigningContext {
        tx: &unsigned,
        input_index: 0,
    };
    assert_eq!(
        Arg::States(states.clone()).resolve(&ctx),
        kcc20_states_value(&states)
    );
}
