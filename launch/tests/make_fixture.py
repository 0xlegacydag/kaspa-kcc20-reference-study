"""Make the test fixture: a chain file in the format of FORMAT.md, from a rehearsal plan of the builder.

    python tests/make_fixture.py PLAN.json [OUT.json]

PLAN.json is the `launch-plan.json` a dry run of the builder writes: thirteen
transactions with a made-up funding outpoint and dry-run keys, with the ids
the builder computed. The fixture keeps what the plan holds and adds what the
chain format wants on top of it. What is made up here, and why the checks of
the sender still mean something on it:

* The plan starts from a coin of 100 KAS; a run allows 30. The paying coin is
  made 70 KAS smaller all along the chain, so every transaction id is worked
  out again, by the SDK. Before that, the SDK is shown to give the plan's own
  ids from the plan's own fields.
* The mass fields and the masses are the plan's: they were calculated for the
  larger paying coin and are not calculated again. An id does not cover them.
* Signature scripts are placeholders of the right length (the byte 0x5a
  repeated): the plan holds none. An id does not cover them either. No
  transaction of the fixture would pass a node.
* The states of the covenant coins are written from the plan's descriptions
  ("minter of issuer: 25 left to mint"). They are the true ones: the harness
  of the study recomputes every lock of the plan from them (see the tests).
* Three probes are made up from the coins that are left at the end. Their
  outputs reuse locks of the plan; the refusals stated for them are invented.

The keys are the plan's dry-run keys, by their public halves only. Alice's key
never locks a plain output in the plan; it was found by matching the lock of
"token coin of Alice: 10 tokens".
"""

import json
import re
import sys
from pathlib import Path

from kaspa import (
    CovenantBinding,
    GenesisCovenantGroup,
    Hash,
    ScriptPublicKey,
    Transaction,
    TransactionInput,
    TransactionOutpoint,
    TransactionOutput,
)

SOMPI_PER_KAS = 100_000_000
FUNDING_VALUE = 30 * SOMPI_PER_KAS
MINT_AMOUNT = 10  # "at most 10 per mint", from the plan's first step
ZERO32 = "00" * 32
PLACEHOLDER_BYTE = "5a"

# X-only public keys of the plan's dry-run keys.
KEYS = {
    "issuer": "d793631af7aa0e709439dd47fc001acd0b0727670b6670ea528ac83cb0127f4a",
    "alice": "ab5d2e79cfd621b1b027ffb24e2453ed7fb571ba9a841ff0e2473466cabd168d",
    "bob": "ad1d02fb804c18df3434bb8e259694120512c64136d877390d9eb46707fddec2",
    "payer": "0ce472ae5d8993e7609ee4ef33b344f6b8499a1259374bdf528f82240985bf03",
}

MINTER = re.compile(r"^minter of (\w+): (\d+) left to mint$")
SEED = re.compile(r"^seed of (\w+)$")
TOKEN = re.compile(r"^token coin of (\w+): (\d+) tokens(, open to payments)?$")
DEPOSIT = re.compile(r"^deposit back to (\w+)$")
CHANGE = "paying coin of the fee payer"


def pay_to_key(name: str) -> str:
    return "20" + KEYS[name] + "ac"


def described(what: str) -> tuple:
    """(role, to, state) of an output, from the plan's words about it."""
    if what == CHANGE:
        return "change", "payer", None
    if found := DEPOSIT.match(what):
        return "deposit", found[1].lower(), None
    if found := MINTER.match(what):
        state = {
            "contract": "PublicMint",
            "remaining": int(found[2]),
            "mint_amount": MINT_AMOUNT,
            "owner": KEYS[found[1].lower()],
            "extension_commitment": ZERO32,
        }
        return "covenant", None, state
    if found := SEED.match(what):
        return "covenant", None, {"contract": "TokenSeed", "owner": KEYS[found[1].lower()], "extension_commitment": ZERO32}
    if found := TOKEN.match(what):
        state = {
            "contract": "KCC20",
            "amount": int(found[2]),
            "owner": KEYS[found[1].lower()],
            "owner_scheme": 0,
            # "open to payments": the amount-threshold scheme with a threshold of zero.
            "borrow_scheme": 1 if found[3] else 0,
            "borrow_guard": ZERO32,
            "extension_commitment": ZERO32,
        }
        return "covenant", None, state
    raise SystemExit(f"an output of the plan is described in words this script does not know: {what!r}")


def transaction_id(transaction: dict) -> str:
    """The id the SDK gives a transaction of the chain format."""
    inputs = [
        TransactionInput(
            TransactionOutpoint(Hash(item["transaction_id"]), item["index"]),
            bytes.fromhex(item["signature_script"]),
            sequence=item["sequence"],
            sig_op_count=item["sig_op_count"],
            compute_budget=item["compute_budget"],
        )
        for item in transaction["inputs"]
    ]
    outputs = []
    for item in transaction["outputs"]:
        bound = item["covenant_binding"]
        binding = CovenantBinding(bound["authorizing_input"], Hash(bound["covenant_id"])) if bound else None
        outputs.append(
            TransactionOutput(item["value"], ScriptPublicKey(item["script_public_key_version"], item["script_public_key"]), binding)
        )
    built = Transaction(
        transaction["version"],
        inputs,
        outputs,
        lock_time=transaction["lock_time"],
        subnetwork_id=bytes.fromhex(transaction["subnetwork_id"]),
        gas=transaction["gas"],
        payload=bytes.fromhex(transaction["payload"]),
        mass=transaction["mass"],
    )
    built.finalize()
    return built.id


def plan_ids_reproduced(plan: dict) -> None:
    """The SDK gives the plan's own ids from the plan's own fields: the method of the conversion holds."""
    for step in plan["steps"]:
        as_chain = {
            "version": 1,
            "lock_time": 0,
            "subnetwork_id": "00" * 20,
            "gas": 0,
            "payload": "",
            "mass": step["storage_mass_written"],
            "inputs": [
                {
                    "transaction_id": item["outpoint"]["transaction_id"],
                    "index": item["outpoint"]["index"],
                    "sequence": 0,
                    "sig_op_count": 0,
                    "compute_budget": item["compute_budget"],
                    "signature_script": "",
                }
                for item in step["inputs"]
            ],
            "outputs": step["outputs"],
        }
        if transaction_id(as_chain) != step["transaction_id"]:
            raise SystemExit(f"the SDK does not give the plan's id for {step['step']!r}")


def skeleton(name: str, what: str, expect: str) -> dict:
    return {
        "name": name,
        "what": what,
        "expect": expect,
        "transaction_id": None,
        "version": 1,
        "lock_time": 0,
        "subnetwork_id": "00" * 20,
        "gas": 0,
        "payload": "",
    }


def convert(plan: dict) -> dict:
    plan_ids_reproduced(plan)
    shift = plan["totals"]["starting_coin"] - FUNDING_VALUE
    funding = {
        "transaction_id": plan["funding_outpoint"]["transaction_id"],
        "index": plan["funding_outpoint"]["index"],
        "value": FUNDING_VALUE,
        "script_public_key_version": 0,
        "script_public_key": pay_to_key("issuer"),
        "owner": "issuer",
    }
    new_id = {}  # the plan's id of a step -> its id in the fixture
    made = {(funding["transaction_id"], funding["index"]): ("funding", funding["value"], funding["script_public_key"], None)}
    locks = {}  # the plan's words about a covenant coin -> (script, state)
    steps = []
    for step in plan["steps"]:
        transaction = skeleton(step["step"], step["what"], "accepted")
        transaction["mass"] = step["storage_mass_written"]
        transaction["inputs"] = []
        for item in step["inputs"]:
            old = item["outpoint"]
            key = (new_id.get(old["transaction_id"], old["transaction_id"]), old["index"])
            source, value, script, covenant = made[key]
            transaction["inputs"].append(
                {
                    "transaction_id": key[0],
                    "index": key[1],
                    "sequence": 0,
                    "sig_op_count": 0,
                    "compute_budget": item["compute_budget"],
                    "signature_script": PLACEHOLDER_BYTE * item["signature_script_bytes"],
                    "spends": {
                        "from": source,
                        "value": value,
                        "script_public_key_version": 0,
                        "script_public_key": script,
                        "covenant_id": covenant,
                        "what": item["what"],
                    },
                }
            )
        transaction["outputs"] = []
        for item in step["outputs"]:
            role, to, state = described(item["what"])
            if role != "covenant" and item["script_public_key"] != pay_to_key(to):
                raise SystemExit(f"{step['step']!r}: {item['what']!r} is not locked to the key of {to!r}")
            if role == "covenant":
                locks[item["what"]] = (item["script_public_key"], state)
            transaction["outputs"].append(
                {
                    "value": item["value"] - shift if role == "change" else item["value"],
                    "script_public_key_version": item["script_public_key_version"],
                    "script_public_key": item["script_public_key"],
                    "covenant_binding": item["covenant_binding"],
                    "role": role,
                    "to": to,
                    "state": state,
                    "what": item["what"],
                }
            )
        transaction["fee"] = step["fee"]
        transaction["fee_floor"] = step["fee_floor"]
        transaction["masses"] = {
            "compute_mass": step["masses"]["compute_mass"],
            "transient_mass": step["masses"]["transient_mass"],
            "calculated_storage_mass": step["masses"]["calculated_storage_mass"],
            "fee_mass": step["fee_mass"],
        }
        transaction["gate"] = {
            "scripts": step["verdicts"]["scripts"],
            "consensus": step["verdicts"]["consensus_on_submission"],
            "mempool": step["verdicts"]["mempool"],
            "block": step["verdicts"]["block"],
            "refusal": None,
        }
        transaction["transaction_id"] = new_id[step["transaction_id"]] = transaction_id(transaction)
        for number, output in enumerate(transaction["outputs"]):
            bound = output["covenant_binding"]
            made[(transaction["transaction_id"], number)] = (
                {"step": transaction["name"], "output": number},
                output["value"],
                output["script_public_key"],
                bound["covenant_id"] if bound else None,
            )
        steps.append(transaction)

    spent = {(i["transaction_id"], i["index"]) for step in steps for i in step["inputs"]}
    left = {}  # the plan's words about a coin unspent at the end -> its outpoint
    for step in steps:
        for number, output in enumerate(step["outputs"]):
            if (step["transaction_id"], number) not in spent:
                left[output["what"]] = (step["transaction_id"], number)

    def probe(name: str, what: str, spends: list, makes: list) -> dict:
        transaction = skeleton(name, what, "refused")
        transaction["mass"] = 79000
        transaction["inputs"] = []
        for words, budget in spends:
            source, value, script, covenant = made[left[words]]
            transaction["inputs"].append(
                {
                    "transaction_id": left[words][0],
                    "index": left[words][1],
                    "sequence": 0,
                    "sig_op_count": 0,
                    "compute_budget": budget,
                    "signature_script": PLACEHOLDER_BYTE * (66 if covenant is None else 4200),
                    "spends": {
                        "from": source,
                        "value": value,
                        "script_public_key_version": 0,
                        "script_public_key": script,
                        "covenant_id": covenant,
                        "what": words,
                    },
                }
            )
        fee = 1_100_000
        transaction["outputs"] = []
        for words in makes:
            script, state = locks[words]
            transaction["outputs"].append(
                {
                    "value": plan["totals"]["coin_value"],
                    "script_public_key_version": 0,
                    "script_public_key": script,
                    "covenant_binding": {"authorizing_input": 0, "covenant_id": plan["covenant_id"]},
                    "role": "covenant",
                    "to": None,
                    "state": state,
                    "what": words,
                }
            )
        paid_in = sum(item["spends"]["value"] for item in transaction["inputs"])
        transaction["outputs"].append(
            {
                "value": paid_in - plan["totals"]["coin_value"] * len(makes) - fee,
                "script_public_key_version": 0,
                "script_public_key": pay_to_key("payer"),
                "covenant_binding": None,
                "role": "change",
                "to": "payer",
                "state": None,
                "what": CHANGE,
            }
        )
        transaction["fee"] = fee
        transaction["fee_floor"] = 1_000_000
        transaction["masses"] = {"compute_mass": 8000, "transient_mass": 20000, "calculated_storage_mass": 79000, "fee_mass": 10000}
        transaction["gate"] = {
            "scripts": False,
            "consensus": False,
            "mempool": False,
            "block": False,
            "refusal": {"layer": "scripts", "input": 0, "rule": None, "message": "made up for the test fixture"},
        }
        transaction["transaction_id"] = transaction_id(transaction)
        return transaction

    probes = [
        probe(
            "P1 more out than in",
            "made up for the tests: Alice's coin of 3 tokens comes out as a coin of 10",
            [("token coin of Alice: 3 tokens", 14), (CHANGE, 10)],
            ["token coin of Alice: 10 tokens"],
        ),
        probe(
            "P2 another owner's coin",
            "made up for the tests: Bob's coin of 4 tokens comes out as a coin of Alice",
            [("token coin of Bob: 4 tokens", 14), (CHANGE, 10)],
            ["token coin of Alice: 6 tokens"],
        ),
        probe(
            "P3 seed makes tokens",
            "made up for the tests: the seed creates a coin that already holds 4 tokens",
            [("seed of issuer", 4), (CHANGE, 10)],
            ["seed of issuer", "token coin of Bob: 4 tokens"],
        ),
    ]

    first = steps[0]
    bare_outputs = [
        TransactionOutput(o["value"], ScriptPublicKey(o["script_public_key_version"], o["script_public_key"]), None)
        for o in first["outputs"]
    ]
    bare = Transaction(
        1,
        [TransactionInput(TransactionOutpoint(Hash(funding["transaction_id"]), funding["index"]), b"", sequence=0, sig_op_count=0, compute_budget=10)],
        bare_outputs,
        lock_time=0,
        subnetwork_id=bytes(20),
        gas=0,
        payload=b"",
        mass=first["mass"],
    )
    covenant_outputs = [number for number, o in enumerate(first["outputs"]) if o["role"] == "covenant"]
    bare.populate_genesis_covenants([GenesisCovenantGroup(authorizing_input=0, outputs=covenant_outputs)])
    derived = {bare.outputs[number].to_dict()["covenant"]["covenantId"] for number in covenant_outputs}
    if derived != {plan["covenant_id"]}:
        raise SystemExit("the covenant id of the plan does not survive the smaller paying coin")

    totals = plan["totals"]
    return {
        "format": "kcc20-launch-chain/1",
        "network": "testnet-10",
        "built_at_utc": "2026-01-01T00:00:00Z",
        "nothing_was_sent": True,
        "token_name": "fixture-token",
        "coin_value": totals["coin_value"],
        "feerate": 110,
        "fee_rule": plan["fee_rule"],
        "fee_cap_total": 15 * SOMPI_PER_KAS,
        "funding": funding,
        "parties": {name: {"x_only_public_key": key, "script_public_key": pay_to_key(name)} for name, key in KEYS.items()},
        "covenant_id": plan["covenant_id"],
        "steps": steps,
        "probes": probes,
        "totals": {
            "fees": totals["fees_total"],
            "locked_at_peak": totals["locked_at_peak"],
            "locked_at_the_end": totals["locked_at_the_end"],
            "deposits_returned": totals["deposits_returned"],
            "change_at_the_end": totals["paying_coin_at_the_end"] - shift,
            "tokens_minted": totals["tokens_minted"],
        },
    }


def main(argv: list) -> None:
    if not 1 <= len(argv) <= 2:
        raise SystemExit(__doc__)
    out = Path(argv[1]) if len(argv) == 2 else Path(__file__).resolve().parent / "fixture-chain.json"
    chain = convert(json.loads(Path(argv[0]).read_bytes()))
    with open(out, "w", encoding="utf-8", newline="\n") as file:
        file.write(json.dumps(chain, indent=1) + "\n")
    print(f"written: {out} ({len(chain['steps'])} steps, {len(chain['probes'])} probes)")


if __name__ == "__main__":
    main(sys.argv[1:])
