"""Check a prepared chain of KCC-20 transactions and send it to Kaspa testnet-10.

TEST NETWORK ONLY. The program accepts no other network, and it holds no keys:
every signature is already inside the chain file, made by the builder. See
FORMAT.md for the two files that pass between the builder and this program,
and README.md for the order of a run.

    python launch_send.py prepare --issuer-address kaspatest:... --out request.json
    python launch_send.py check chain.json --party issuer=kaspatest:... --party alice=... --party bob=... --harness DIR
    python launch_send.py send chain.json --party ... --harness DIR --record DIR --yes-send-to-testnet-10
    python launch_send.py status chain.json --party ...

`prepare`, `check --online` and `status` only read the network. `send` is the
only command that submits anything, and only with its flag and with a harness
(`--harness`, or KCC20_HARNESS_DIR): the folder of `kcc20_harness.py`, by which
the lock of every covenant output is recomputed from its state. After a stop
at a refused step or a lost answer, `send` hands that step over again only
with `--again-after-a-stop`.

Exit codes: 0 finished; 1 usage or check failure; 2 a step was refused;
3 no answer to a submission; 4 submitted but not seen; 5 a forbidden move was
accepted; 6 the picture on chain does not fit the file; 7 the node could not
be asked or read after the checks had passed (nothing was submitted in that
step); 8 the record could not be written (nothing more was submitted);
130 interrupted from the keyboard.
"""

import argparse
import asyncio
import datetime
import hashlib
import importlib.util
import json
import math
import os
import sys
import time
from pathlib import Path

from kaspa import (
    Address,
    CovenantBinding,
    GenesisCovenantGroup,
    Hash,
    Resolver,
    RpcClient,
    ScriptPublicKey,
    Transaction,
    TransactionInput,
    TransactionOutpoint,
    TransactionOutput,
    UtxoEntryReference,
    address_from_script_public_key,
    pay_to_address_script,
)

# --------------------------------------------------------------------------
# Constants. None of them can be changed from the command line.
# --------------------------------------------------------------------------

NETWORK_ID = "testnet-10"
NETWORK_TYPE = "testnet"
ADDRESS_PREFIX = "kaspatest:"

REQUEST_FORMAT = "kcc20-launch-request/1"
CHAIN_FORMAT = "kcc20-launch-chain/1"

SOMPI_PER_KAS = 100_000_000

# Hard limits of a run.
MAX_FUNDING = 30 * SOMPI_PER_KAS  # the one plain coin the run starts from
MAX_TOTAL_FEES = 15 * SOMPI_PER_KAS  # sum of the fees of all steps
COIN_VALUE = 1 * SOMPI_PER_KAS  # value of every covenant coin
MAX_STEPS = 20
MAX_PROBES = 10

MIN_FEERATE = 100  # sompi per gram: the least a default node relays for
# Bounds for the fields a transaction id does not cover. They only catch nonsense: whether the
# numbers are right is for a node to say.
MAX_COMPUTE_BUDGET = 1_000  # per input
MAX_MASS = 500_000

REFUSAL_MARK = "Rejected transaction"  # how a node's own refusal begins
# Words by which a refusal is taken for a failed script. Loose on purpose: the text is recorded whole.
SCRIPT_FAILURE_MARKS = ("signature script", "script ran", "script error", "verification failed")

EXIT_OK = 0
EXIT_CHECK = 1
EXIT_REFUSED = 2
EXIT_NO_ANSWER = 3
EXIT_NOT_SEEN = 4
EXIT_FORBIDDEN_ACCEPTED = 5
EXIT_INCONSISTENT = 6
EXIT_NODE = 7
EXIT_RECORD = 8


class Timing:
    """Waiting times. The tests replace them; the command line cannot."""

    poll_seconds = 1.0
    seen_polls = 120  # after an accepted submission: how long to look for the outputs
    lost_polls = 60  # after a lost answer: how long to look for the outputs
    read_attempts = 4
    read_pause_seconds = 2.0
    connect_timeout = 60
    answer_timeout = 60  # for one question to the node; a submission without an answer by then is a lost answer


class Stop(Exception):
    """The program ends here with this exit code and this last line."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
        self.said = False  # whether the last line is on screen already


class WrongNode(Stop):
    """The node is not a synced testnet-10 node."""

    def __init__(self, message: str):
        super().__init__(EXIT_CHECK, message)


class NoAnswer(Exception):
    """A submission ended without the node's answer: the node may have taken the transaction."""


INTERRUPTED: dict = {}  # filled when an interrupt lands on a hand-over: which transaction it was


def say(line: str = "") -> None:
    print(line, flush=True)


def kas(sompi: int) -> str:
    return f"{sompi / SOMPI_PER_KAS:.8f}"


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# The shape of the chain file
# --------------------------------------------------------------------------

HEX_DIGITS = set("0123456789abcdef")


def is_hex(value, size: int | None = None) -> bool:
    """Lowercase hex of whole bytes; `size` is the exact number of bytes when given."""
    if not isinstance(value, str) or len(value) % 2 or not set(value) <= HEX_DIGITS:
        return False
    return size is None or len(value) == 2 * size


def is_uint(value, bits: int) -> bool:
    return type(value) is int and 0 <= value < 2**bits


KINDS = {
    "text": (lambda v: isinstance(v, str), "a text"),
    "bool": (lambda v: isinstance(v, bool), "true or false"),
    "u8": (lambda v: is_uint(v, 8), "a whole number from 0 to 255"),
    "u16": (lambda v: is_uint(v, 16), "a whole number from 0 to 65535"),
    "u32": (lambda v: is_uint(v, 32), "a whole number that fits 32 bits"),
    "u64": (lambda v: is_uint(v, 64), "a whole number that fits 64 bits"),
    "hex": (is_hex, "lowercase hex"),
    "hex20": (lambda v: is_hex(v, 20), "40 lowercase hex characters"),
    "hex32": (lambda v: is_hex(v, 32), "64 lowercase hex characters"),
    "object": (lambda v: isinstance(v, dict), "an object"),
    "list": (lambda v: isinstance(v, list), "a list"),
    "any": (lambda v: True, "anything"),
}

TOP_SHAPE = {
    "format": "text",
    "network": "text",
    "built_at_utc": "text",
    "nothing_was_sent": "bool",
    "token_name": "text",
    "coin_value": "u64",
    "feerate": "u64",
    "fee_rule": "text",
    "fee_cap_total": "u64",
    "funding": "object",
    "parties": "object",
    "covenant_id": "hex32",
    "steps": "list",
    "probes": "list",
    "totals": "object",
}
FUNDING_SHAPE = {
    "transaction_id": "hex32",
    "index": "u32",
    "value": "u64",
    "script_public_key_version": "u16",
    "script_public_key": "hex",
    "owner": "text",
}
PARTY_SHAPE = {"x_only_public_key": "hex32", "script_public_key": "hex"}
TOTALS_SHAPE = {
    "fees": "u64",
    "locked_at_peak": "u64",
    "locked_at_the_end": "u64",
    "deposits_returned": "u64",
    "change_at_the_end": "u64",
    "tokens_minted": "u64",
}
TRANSACTION_SHAPE = {
    "name": "text",
    "what": "text",
    "expect": "text",
    "transaction_id": "hex32",
    "version": "u16",
    "lock_time": "u64",
    "subnetwork_id": "hex20",
    "gas": "u64",
    "payload": "hex",
    "mass": "u64",
    "inputs": "list",
    "outputs": "list",
    "fee": "u64",
    "fee_floor": "u64",
    "masses": "object",
    "gate": "object",
}
INPUT_SHAPE = {
    "transaction_id": "hex32",
    "index": "u32",
    "sequence": "u64",
    "sig_op_count": "u8",
    "compute_budget": "u16",
    "signature_script": "hex",
    "spends": "object",
}
SPENDS_SHAPE = {
    "from": "any",
    "value": "u64",
    "script_public_key_version": "u16",
    "script_public_key": "hex",
    "covenant_id": "hex32?",
}
OUTPUT_SHAPE = {
    "value": "u64",
    "script_public_key_version": "u16",
    "script_public_key": "hex",
    "covenant_binding": "object?",
    "role": "text",
    "to": "text?",
    "state": "object?",
}
BINDING_SHAPE = {"authorizing_input": "u16", "covenant_id": "hex32"}
GATE_SHAPE = {"scripts": "bool", "consensus": "bool", "mempool": "bool", "block": "bool", "refusal": "object?"}


def shape(problems: list, where: str, item, spec: dict) -> bool:
    """Whether `item` has every field of `spec` with a value of the right kind. Extra fields are let be."""
    if not isinstance(item, dict):
        problems.append(f"{where}: is not an object")
        return False
    fits = True
    for field, kind in spec.items():
        if field not in item:
            problems.append(f"{where}: the field {field!r} is missing")
            fits = False
            continue
        optional = kind.endswith("?")
        if item[field] is None and optional:
            continue
        test, words = KINDS[kind.rstrip("?")]
        if not test(item[field]):
            problems.append(f"{where}: the field {field!r} is not {words}{' or null' if optional else ''}")
            fits = False
    return fits


def label(group: str, position: int, transaction) -> str:
    name = transaction.get("name") if isinstance(transaction, dict) else None
    return f"{group} {position + 1} ({name!r})" if isinstance(name, str) else f"{group} {position + 1}"


def check_shape(data) -> list:
    """Every field the program reads is there and of the right kind. Returns the problems."""
    problems: list = []
    if not shape(problems, "file", data, TOP_SHAPE):
        return problems
    shape(problems, "funding", data["funding"], FUNDING_SHAPE)
    shape(problems, "totals", data["totals"], TOTALS_SHAPE)
    if not data["parties"]:
        problems.append("parties: none are named")
    for name, party in data["parties"].items():
        shape(problems, f"party {name!r}", party, PARTY_SHAPE)
    for group in ("steps", "probes"):
        for position, transaction in enumerate(data[group]):
            where = label(group[:-1], position, transaction)
            if not shape(problems, where, transaction, TRANSACTION_SHAPE):
                continue
            shape(problems, f"{where}, gate", transaction["gate"], GATE_SHAPE)
            if not transaction["inputs"]:
                problems.append(f"{where}: has no inputs")
            if not transaction["outputs"]:
                problems.append(f"{where}: has no outputs")
            for number, tx_input in enumerate(transaction["inputs"]):
                at = f"{where}, input {number}"
                if not shape(problems, at, tx_input, INPUT_SHAPE):
                    continue
                if shape(problems, f"{at}, spends", tx_input["spends"], SPENDS_SHAPE):
                    source = tx_input["spends"]["from"]
                    named = isinstance(source, dict) and isinstance(source.get("step"), str) and is_uint(source.get("output"), 32)
                    if source != "funding" and not named:
                        problems.append(f'{at}, spends: "from" is neither "funding" nor a step and an output number')
            for number, output in enumerate(transaction["outputs"]):
                at = f"{where}, output {number}"
                if shape(problems, at, output, OUTPUT_SHAPE) and output["covenant_binding"] is not None:
                    shape(problems, f"{at}, covenant binding", output["covenant_binding"], BINDING_SHAPE)
    names = [t["name"] for group in ("steps", "probes") for t in data[group] if isinstance(t, dict) and isinstance(t.get("name"), str)]
    for name in sorted({name for name in names if names.count(name) > 1}):
        problems.append(f"file: the name {name!r} is used by more than one transaction")
    return problems


# --------------------------------------------------------------------------
# The chain as coins: what each transaction spends and makes
# --------------------------------------------------------------------------


def funding_coin(data: dict) -> dict:
    funding = data["funding"]
    return {
        "key": (funding["transaction_id"], funding["index"]),
        "value": funding["value"],
        "version": funding["script_public_key_version"],
        "script": funding["script_public_key"],
        "covenant_id": None,
        "role": "funding",
        "to": funding["owner"],
        "state": None,
        "label": "the funding coin",
    }


def output_coins(transaction: dict) -> list:
    """The coins a transaction makes, in the order of its outputs."""
    coins = []
    for number, output in enumerate(transaction["outputs"]):
        binding = output["covenant_binding"]
        coins.append(
            {
                "key": (transaction["transaction_id"], number),
                "value": output["value"],
                "version": output["script_public_key_version"],
                "script": output["script_public_key"],
                "covenant_id": binding["covenant_id"] if binding else None,
                "role": output["role"],
                "to": output["to"],
                "state": output["state"],
                "label": f"output {number} of {transaction['name']!r}",
            }
        )
    return coins


def spent_keys(transaction: dict) -> list:
    return [(tx_input["transaction_id"], tx_input["index"]) for tx_input in transaction["inputs"]]


def spent_coin(tx_input: dict) -> dict:
    """The coin an input says it spends, as its `spends` block describes it."""
    spends = tx_input["spends"]
    return {
        "key": (tx_input["transaction_id"], tx_input["index"]),
        "value": spends["value"],
        "version": spends["script_public_key_version"],
        "script": spends["script_public_key"],
        "covenant_id": spends["covenant_id"],
        "label": spends.get("what") or "a coin",
    }


def unspent_after_each_step(data: dict) -> list:
    """`result[k]`: the coins unspent once the first k steps are on chain, by outpoint. `result[0]` is the funding coin."""
    funding = funding_coin(data)
    current = {funding["key"]: funding}
    result = [dict(current)]
    for step in data["steps"]:
        for key in spent_keys(step):
            current.pop(key, None)
        for coin in output_coins(step):
            current[coin["key"]] = coin
        result.append(dict(current))
    return result


def outpoint_text(key: tuple) -> str:
    return f"{key[0]}:{key[1]}"


def address_of_script(version: int, script: str) -> str:
    return address_from_script_public_key(ScriptPublicKey(version, script), NETWORK_TYPE).to_string()


# --------------------------------------------------------------------------
# Rebuilding a transaction from the fields of the file
# --------------------------------------------------------------------------


def build_transaction(transaction: dict, entries: list | None = None, with_bindings: bool = True) -> Transaction:
    """The transaction as an SDK object, from the fields of the file alone.

    `entries` are the node's own UTXO entries of the spent coins, one per
    input, for a transaction that is about to be submitted. Without bindings
    the outputs carry no covenant binding: the form from which the SDK derives
    a genesis covenant id by itself.
    """
    inputs = []
    for number, item in enumerate(transaction["inputs"]):
        more = {}
        if entries is not None:
            more["utxo"] = UtxoEntryReference.from_dict(entries[number])
        inputs.append(
            TransactionInput(
                TransactionOutpoint(Hash(item["transaction_id"]), item["index"]),
                bytes.fromhex(item["signature_script"]),
                sequence=item["sequence"],
                sig_op_count=item["sig_op_count"],
                compute_budget=item["compute_budget"],
                **more,
            )
        )
    outputs = []
    for item in transaction["outputs"]:
        binding = None
        if with_bindings and item["covenant_binding"] is not None:
            bound = item["covenant_binding"]
            binding = CovenantBinding(bound["authorizing_input"], Hash(bound["covenant_id"]))
        script = ScriptPublicKey(item["script_public_key_version"], item["script_public_key"])
        outputs.append(TransactionOutput(item["value"], script, binding))
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
    # The SDK works the id out when the object is made; asked again, it reads the object as it is now.
    built.finalize()
    return built


def differences_outside_the_id(built: Transaction, transaction: dict) -> list:
    """Where the built object differs from the file in what the id does not cover.

    Equal ids say nothing about the signature scripts, the mass field and the
    compute budgets, so these are read back from the object and compared.
    """
    shown = built.to_dict()
    found = []
    if shown.get("mass") != transaction["mass"]:
        found.append(f"the mass field reads {shown.get('mass')}, the file says {transaction['mass']}")
    if len(shown["inputs"]) != len(transaction["inputs"]):
        return found + ["the number of inputs differs"]
    for number, (have, want) in enumerate(zip(shown["inputs"], transaction["inputs"])):
        if have.get("signatureScript") != want["signature_script"]:
            found.append(f"input {number}: the signature script differs from the file")
        if have.get("computeBudget") != want["compute_budget"]:
            found.append(f"input {number}: the compute budget reads {have.get('computeBudget')}, the file says {want['compute_budget']}")
        if have.get("sigOpCount") != want["sig_op_count"]:
            found.append(f"input {number}: the signature operation count differs from the file")
    return found


# --------------------------------------------------------------------------
# The checks of the chain file (offline)
# --------------------------------------------------------------------------


def check_basics(data: dict) -> list:
    """a. Format, network, limits and what the builder says it expects."""
    problems = []
    if data["format"] != CHAIN_FORMAT:
        problems.append(f"file: the format is {data['format']!r}, not {CHAIN_FORMAT!r}")
    if data["network"] != NETWORK_ID:
        problems.append(f"file: the network is {data['network']!r}, not {NETWORK_ID!r}: wrong network")
    if data["nothing_was_sent"] is not True:
        problems.append("file: nothing_was_sent is not true: the builder does not say that it sent nothing")
    if data["coin_value"] != COIN_VALUE:
        problems.append(f"file: the coin value is {kas(data['coin_value'])} KAS, the run allows exactly {kas(COIN_VALUE)}")
    if data["funding"]["value"] > MAX_FUNDING:
        problems.append(
            f"funding: the coin holds {kas(data['funding']['value'])} KAS, above the hard limit of {kas(MAX_FUNDING)} KAS"
        )
    if data["feerate"] < MIN_FEERATE:
        problems.append(f"file: the feerate {data['feerate']} is below {MIN_FEERATE} sompi per gram")
    if not 1 <= len(data["steps"]) <= MAX_STEPS:
        problems.append(f"file: {len(data['steps'])} steps; the run allows 1 to {MAX_STEPS}")
    if len(data["probes"]) > MAX_PROBES:
        problems.append(f"file: {len(data['probes'])} probes; the run allows at most {MAX_PROBES}")
    for position, step in enumerate(data["steps"]):
        where = label("step", position, step)
        gate = step["gate"]
        if step["expect"] != "accepted":
            problems.append(f'{where}: expect is {step["expect"]!r}, a step must say "accepted"')
        failed = [layer for layer in ("scripts", "consensus", "mempool", "block") if gate[layer] is not True]
        if failed:
            problems.append(f"{where}: the builder's gate did not pass it ({', '.join(failed)})")
        if gate["refusal"] is not None:
            problems.append(f"{where}: the builder's gate recorded a refusal")
    for position, probe in enumerate(data["probes"]):
        where = label("probe", position, probe)
        gate = probe["gate"]
        if probe["expect"] != "refused":
            problems.append(f'{where}: expect is {probe["expect"]!r}, a probe must say "refused"')
        if gate["scripts"] is not False:
            problems.append(f"{where}: the builder's gate did not refuse it by its scripts")
        if gate["refusal"] is None:
            problems.append(f"{where}: the builder's gate recorded no refusal")
    return problems


def check_parties(data: dict, addresses: dict) -> list:
    """b. The parties of the file are the ones named on the command line, by their addresses."""
    problems = []
    parties = data["parties"]
    if set(parties) != set(addresses):
        problems.append(
            f"parties: the file names {sorted(parties)}, the command line names {sorted(addresses)}: they must be the same"
        )
    for name, party in parties.items():
        if party["script_public_key"] != "20" + party["x_only_public_key"] + "ac":
            problems.append(f"party {name!r}: its script is not the pay-to-public-key script of its key")
        address = addresses.get(name)
        if address is None:
            continue
        if not address.startswith(ADDRESS_PREFIX):
            problems.append(f"party {name!r}: the address given does not start with {ADDRESS_PREFIX}")
            continue
        try:
            script = pay_to_address_script(Address(address))
        except Exception as error:
            problems.append(f"party {name!r}: the address given does not read as an address ({error})")
            continue
        if (script.version, script.script) != (0, party["script_public_key"]):
            problems.append(
                f"party {name!r}: the address given does not match the file: it pays to {script.script}, "
                f"the file says {party['script_public_key']}"
            )
    scripts = [party["script_public_key"] for party in parties.values()]
    if len(set(scripts)) != len(scripts):
        problems.append("parties: two parties have the same script")
    funding = data["funding"]
    owner = parties.get(funding["owner"])
    if "issuer" in parties and funding["owner"] != "issuer":
        problems.append(f"funding: the owner is {funding['owner']!r}; with a party named 'issuer' the funding coin must be the issuer's")
    if owner is None:
        problems.append(f"funding: the owner {funding['owner']!r} is not a party")
    elif (funding["script_public_key_version"], funding["script_public_key"]) != (0, owner["script_public_key"]):
        problems.append(f"funding: the coin is not locked to the script of its owner {funding['owner']!r}")
    return problems


def check_rebuild(data: dict) -> list:
    """c. Every transaction, rebuilt by the SDK from the fields, has the id the file states."""
    problems = []
    for group in ("steps", "probes"):
        for position, transaction in enumerate(data[group]):
            where = label(group[:-1], position, transaction)
            try:
                built = build_transaction(transaction)
            except Exception as error:
                problems.append(f"{where}: cannot be rebuilt from its fields ({error})")
                continue
            if built.id != transaction["transaction_id"]:
                problems.append(
                    f"{where}: id mismatch: rebuilt from the fields it is {built.id}, the file says {transaction['transaction_id']}"
                )
            for difference in differences_outside_the_id(built, transaction):
                problems.append(f"{where}: {difference}")
            plain = (("version", 1), ("lock_time", 0), ("gas", 0), ("payload", ""), ("subnetwork_id", "00" * 20))
            for field, only in plain:
                if transaction[field] != only:
                    problems.append(f"{where}: {field} is {transaction[field]!r}; a transaction of this run has only {only!r} there")
            for number, tx_input in enumerate(transaction["inputs"]):
                for field in ("sequence", "sig_op_count"):
                    if tx_input[field] != 0:
                        problems.append(f"{where}, input {number}: {field} is {tx_input[field]}; a transaction of this run has only 0 there")
            if not 0 < transaction["mass"] <= MAX_MASS:
                problems.append(f"{where}: the mass field {transaction['mass']} is not between 1 and {MAX_MASS}")
            for number, tx_input in enumerate(transaction["inputs"]):
                if not tx_input["signature_script"]:
                    problems.append(f"{where}, input {number}: empty signature script")
                if tx_input["compute_budget"] > MAX_COMPUTE_BUDGET:
                    problems.append(
                        f"{where}, input {number}: the compute budget {tx_input['compute_budget']} is above {MAX_COMPUTE_BUDGET}"
                    )
    return problems


def compare_spent(where: str, tx_input: dict, coin: dict) -> list:
    """An input's outpoint and `spends` block against the coin it names."""
    problems = []
    claimed = spent_coin(tx_input)
    if claimed["key"] != coin["key"]:
        problems.append(
            f"{where}: the outpoint {outpoint_text(claimed['key'])} is not {coin['label']} ({outpoint_text(coin['key'])})"
        )
    if claimed["value"] != coin["value"]:
        problems.append(f"{where}: spends says the value is {claimed['value']}, {coin['label']} holds {coin['value']}")
    if (claimed["version"], claimed["script"]) != (coin["version"], coin["script"]):
        problems.append(f"{where}: spends states another script than {coin['label']} has")
    if claimed["covenant_id"] != coin["covenant_id"]:
        problems.append(f"{where}: spends states another covenant id than {coin['label']} carries")
    return problems


def named_coin(data: dict, source, before: int | None):
    """The coin a `spends.from` names: (coin, None) or (None, what is wrong).

    `before` is the number of the step that spends it: only earlier steps
    count. None means any step.
    """
    if source == "funding":
        return funding_coin(data), None
    names = [step["name"] for step in data["steps"]]
    if source["step"] not in names:
        return None, f"the step {source['step']!r} does not exist"
    position = names.index(source["step"])
    if before is not None and position >= before:
        return None, f"the step {source['step']!r} is not an earlier step"
    coins = output_coins(data["steps"][position])
    if source["output"] >= len(coins):
        return None, f"output {source['output']} of the step {source['step']!r} does not exist"
    return coins[source["output"]], None


def check_linkage(data: dict) -> list:
    """d. Steps spend the funding coin or outputs of earlier steps, each once; probes spend what is left."""
    problems = []
    funding = funding_coin(data)
    spent_by: dict = {}
    for position, step in enumerate(data["steps"]):
        where = label("step", position, step)
        for number, tx_input in enumerate(step["inputs"]):
            at = f"{where}, input {number}"
            coin, wrong = named_coin(data, tx_input["spends"]["from"], position)
            if coin is None:
                problems.append(f"{at}: {wrong}")
            else:
                problems += compare_spent(at, tx_input, coin)
            key = (tx_input["transaction_id"], tx_input["index"])
            if key in spent_by:
                problems.append(f"{at}: the outpoint {outpoint_text(key)} was already spent by {spent_by[key]}")
            else:
                spent_by[key] = at
    if funding["key"] not in spent_by:
        problems.append("funding: no step spends the funding coin")
    left = unspent_after_each_step(data)[-1]
    for position, probe in enumerate(data["probes"]):
        where = label("probe", position, probe)
        seen = set()
        for number, tx_input in enumerate(probe["inputs"]):
            at = f"{where}, input {number}"
            key = (tx_input["transaction_id"], tx_input["index"])
            coin, wrong = named_coin(data, tx_input["spends"]["from"], None)
            if coin is None:
                problems.append(f"{at}: {wrong}")
            else:
                problems += compare_spent(at, tx_input, coin)
                if coin["key"] not in left:
                    problems.append(f"{at}: {coin['label']} is not unspent after the last step")
            if key in seen:
                problems.append(f"{at}: the outpoint {outpoint_text(key)} is spent twice by this probe")
            seen.add(key)
    return problems


def check_money(data: dict) -> list:
    """e. Fees: what each transaction burns, the floor, the cap, the hard limit."""
    problems = []
    for group in ("steps", "probes"):
        for position, transaction in enumerate(data[group]):
            where = label(group[:-1], position, transaction)
            spent = sum(tx_input["spends"]["value"] for tx_input in transaction["inputs"])
            made = sum(output["value"] for output in transaction["outputs"])
            fee = transaction["fee"]
            if spent - made != fee:
                problems.append(f"{where}: spends {spent} and makes {made}, a difference of {spent - made}; the file says the fee is {fee}")
            if fee <= 0:
                problems.append(f"{where}: the fee is not above zero")
            if fee < transaction["fee_floor"]:
                problems.append(f"{where}: the fee {fee} is below its floor {transaction['fee_floor']}")
            if fee > MAX_TOTAL_FEES:
                problems.append(f"{where}: the fee {kas(fee)} KAS alone is above the hard limit of {kas(MAX_TOTAL_FEES)} KAS")
    total = sum(step["fee"] for step in data["steps"])
    if total != data["totals"]["fees"]:
        problems.append(f"totals: the fees of the steps sum to {total}, the file says {data['totals']['fees']}")
    if total > data["fee_cap_total"]:
        problems.append(f"totals: the fees of the steps sum to {total}, above the cap of the file {data['fee_cap_total']}")
    if total > MAX_TOTAL_FEES:
        problems.append(f"totals: the fees of the steps sum to {kas(total)} KAS, above the hard limit of {kas(MAX_TOTAL_FEES)} KAS")
    # A probe is meant to be refused. Should a node accept one, the run stops there, so at most one
    # probe's fee is ever paid on top of the steps'.
    dearest = max((probe["fee"] for probe in data["probes"]), default=0)
    if total <= MAX_TOTAL_FEES < total + dearest:
        problems.append(
            f"totals: the fees of the steps and of the dearest probe sum to {kas(total + dearest)} KAS, "
            f"above the hard limit of {kas(MAX_TOTAL_FEES)} KAS"
        )
    return problems


def is_p2sh(script: str) -> bool:
    return len(script) == 70 and script.startswith("aa20") and script.endswith("87")


def check_outputs(data: dict) -> list:
    """f. Every output, of steps and probes, is a covenant coin of this token or pays a party."""
    problems = []
    parties = data["parties"]
    for group in ("steps", "probes"):
        for position, transaction in enumerate(data[group]):
            for number, output in enumerate(transaction["outputs"]):
                where = f"{label(group[:-1], position, transaction)}, output {number}"
                role, binding = output["role"], output["covenant_binding"]
                version, script = output["script_public_key_version"], output["script_public_key"]
                if role == "covenant":
                    if version != 0 or not is_p2sh(script):
                        problems.append(f"{where}: a covenant coin must be locked by a version 0 pay-to-script-hash script")
                    if output["value"] != data["coin_value"]:
                        problems.append(f"{where}: a covenant coin must hold {data['coin_value']}, this one holds {output['value']}")
                    if binding is None:
                        problems.append(f"{where}: a covenant coin without a covenant binding")
                    else:
                        if binding["covenant_id"] != data["covenant_id"]:
                            problems.append(f"{where}: bound to another covenant id ({binding['covenant_id']}) than the token's")
                        if binding["authorizing_input"] >= len(transaction["inputs"]):
                            problems.append(f"{where}: its authorizing input {binding['authorizing_input']} does not exist")
                    if output["to"] is not None:
                        problems.append(f'{where}: a covenant coin names a party in "to"')
                elif role in ("deposit", "change"):
                    if binding is not None:
                        problems.append(f"{where}: a {role} output with a covenant binding")
                    if output["state"] is not None:
                        problems.append(f"{where}: a {role} output with a contract state")
                    party = parties.get(output["to"]) if output["to"] is not None else None
                    if party is None:
                        problems.append(f"{where}: the {role} goes to {output['to']!r}, who is not a party")
                    elif (version, script) != (0, party["script_public_key"]):
                        problems.append(f"{where}: the {role} is said to go to {output['to']!r}, but its script is not that party's")
                else:
                    problems.append(f"{where}: the role {role!r} is not one of covenant, deposit, change")
    return problems


def check_covenant_id(data: dict) -> tuple:
    """g. The covenant id, derived by the SDK from the first step alone. Returns (problems, what was done)."""
    if not data["steps"]:
        return ["covenant id: there is no first step to derive it from"], "not checked"
    first = data["steps"][0]
    groups: dict = {}
    for number, output in enumerate(first["outputs"]):
        if output["role"] == "covenant" and output["covenant_binding"] is not None:
            groups.setdefault(output["covenant_binding"]["authorizing_input"], []).append(number)
    if not groups:
        return [f"covenant id: the first step ({first['name']!r}) makes no covenant coin, so the id cannot be derived"], "not checked"
    try:
        bare = build_transaction(first, with_bindings=False)
        bare.populate_genesis_covenants(
            [GenesisCovenantGroup(authorizing_input=authorizing, outputs=numbers) for authorizing, numbers in sorted(groups.items())]
        )
        bare.finalize()
        derived = [output.to_dict().get("covenant") for output in bare.outputs]
    except Exception as error:
        return [f"covenant id: NOT CHECKED: the SDK could not derive it ({error})"], "not checked"
    problems = []
    for numbers in groups.values():
        for number in numbers:
            got = (derived[number] or {}).get("covenantId")
            if got != data["covenant_id"]:
                problems.append(
                    f"covenant id: for output {number} of the first step the SDK derives {got}, the file says {data['covenant_id']}"
                )
    if bare.id != first["transaction_id"]:
        problems.append("covenant id: the first step with the id the SDK derives is another transaction than the file's")
    count = sum(len(numbers) for numbers in groups.values())
    return problems, f"derived by the SDK from the first step, {count} output(s)"


STATE_BYTES = ("owner", "borrow_guard", "extension_commitment")
CONTRACTS = ("KCC20", "PublicMint", "TokenSeed")


HARNESSES: dict = {}  # folder -> the loaded module: one load per run, so nothing is compiled twice


def load_harness(folder: str):
    """The harness module from `folder`, loaded without writing anything there."""
    path = (Path(folder) / "kcc20_harness.py").resolve()
    if str(path) in HARNESSES:
        return HARNESSES[str(path)]
    spec = importlib.util.spec_from_file_location("kcc20_harness", path)
    module = importlib.util.module_from_spec(spec)
    keep = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # the folder is somebody else's: no bytecode file is left in it
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = keep
    HARNESSES[str(path)] = module
    return module


def harness_sha256(folder: str) -> str | None:
    try:
        return hashlib.sha256((Path(folder) / "kcc20_harness.py").read_bytes()).hexdigest()
    except OSError:
        return None


def check_locks(data: dict, harness_folder: str | None) -> tuple:
    """h. Every covenant output is a coin of the token's contracts, owned by a party.

    Returns (problems, what was done, whether the locks were recomputed). The
    state of each covenant output must be there, name one of the three
    contracts and an owner who is a party; with a harness the lock is then
    recomputed from the state by a second tool and compared.
    """
    problems = []
    stated = []
    keys = {party["x_only_public_key"] for party in data["parties"].values()}
    for group in ("steps", "probes"):
        for position, transaction in enumerate(data[group]):
            for number, output in enumerate(transaction["outputs"]):
                if output["role"] != "covenant":
                    continue
                where = f"{label(group[:-1], position, transaction)}, output {number}"
                state = output["state"]
                if state is None:
                    problems.append(f"{where}: a covenant coin without a state: nothing shows that it is a coin of the token's contracts")
                    continue
                contract = state.get("contract")
                if contract not in CONTRACTS:
                    problems.append(f"{where}: the state names the contract {contract!r}")
                    continue
                owner = state.get("owner")
                if not isinstance(owner, str) or owner not in keys:
                    problems.append(f"{where}: the owner of the coin ({owner}) is not the key of a party named on the command line")
                if contract == "KCC20" and state.get("owner_scheme") != 0:
                    problems.append(
                        f"{where}: the owner scheme is {state.get('owner_scheme')!r}; this run allows only 0 "
                        "(pay to a public key, Schnorr), where the owner is a key"
                    )
                stated.append((where, output))
    if harness_folder is None:
        return problems, f"NOT CHECKED: no --harness given, no lock was recomputed ({len(stated)} covenant outputs)", False
    try:
        harness = load_harness(harness_folder)
    except Exception as error:
        reason = getattr(error, "strerror", None) or str(error)
        return problems + [f"locks: the harness named by --harness could not be loaded ({type(error).__name__}: {reason})"], "NOT CHECKED", False
    for where, output in stated:
        state = dict(output["state"])
        contract = state.pop("contract")
        try:
            for field in STATE_BYTES:
                if field in state:
                    state[field] = bytes.fromhex(state[field])
            lock = bytes(harness.lock(contract, state)).hex()
        except Exception as error:
            problems.append(f"{where}: the lock could not be recomputed from the state ({type(error).__name__}: {error})")
            continue
        if lock != output["script_public_key"]:
            problems.append(f"{where}: the lock recomputed from the state is {lock}, the output carries {output['script_public_key']}")
    return problems, f"recomputed for {len(stated)} covenant outputs", True


def party_of_key(data: dict, key: str) -> str:
    for name, party in data["parties"].items():
        if party["x_only_public_key"] == key:
            return name
    return f"key {key}"


def summary_lines(data: dict) -> list:
    """i. What the chain does, for a reader."""
    left = unspent_after_each_step(data)[-1].values()
    tokens: dict = {}
    minters, seeds, unknown = [], 0, 0
    for coin in left:
        if coin["role"] != "covenant":
            continue
        state = coin["state"] or {}
        contract = state.get("contract")
        if contract == "KCC20" and is_uint(state.get("amount"), 64) and isinstance(state.get("owner"), str):
            holder = party_of_key(data, state["owner"])
            tokens[holder] = tokens.get(holder, 0) + state["amount"]
        elif contract == "PublicMint":
            minters.append(f"{party_of_key(data, str(state.get('owner')))}: {state.get('remaining')} left to mint")
        elif contract == "TokenSeed":
            seeds += 1
        else:
            unknown += 1
    plain: dict = {}
    for coin in left:
        if coin["role"] in ("deposit", "change"):
            plain[coin["to"]] = plain.get(coin["to"], 0) + coin["value"]
    locked = sum(coin["value"] for coin in left if coin["role"] == "covenant")
    lines = [
        f"token name    : {data['token_name']} (a label; nothing on chain carries it)",
        f"covenant id   : {data['covenant_id']}",
        f"funding coin  : {kas(data['funding']['value'])} KAS of {data['funding']['owner']!r}, {outpoint_text(funding_coin(data)['key'])}",
        f"steps         : {len(data['steps'])}, each expected to be accepted",
        f"probes        : {len(data['probes'])}, each expected to be refused",
        f"fees          : {kas(sum(step['fee'] for step in data['steps']))} KAS over the steps "
        f"(cap of the file {kas(data['fee_cap_total'])}, feerate {data['feerate']} sompi per gram)",
        f"left locked   : {kas(locked)} KAS in covenant coins after the last step",
    ]
    for name in sorted(plain):
        lines.append(f"left plain    : {kas(plain[name])} KAS to {name!r} (deposits and change of this chain)")
    if tokens:
        for holder in sorted(tokens):
            lines.append(f"tokens        : {holder} {tokens[holder]}")
        lines.append(f"tokens, total : {sum(tokens.values())} (the file says {data['totals']['tokens_minted']} minted)")
    else:
        lines.append("tokens        : none shown by the states of the unspent coins")
    for minter in minters:
        lines.append(f"minter        : {minter}")
    lines.append(f"seeds         : {seeds}")
    if unknown:
        lines.append(f"no state      : {unknown} unspent covenant coin(s) carry no readable state")
    for position, step in enumerate(data["steps"]):
        lines.append(f"  step {position + 1:>2}  {step['name']}: {step['what']} [fee {kas(step['fee'])}]")
    for position, probe in enumerate(data["probes"]):
        lines.append(f"  probe {position + 1:>1}  {probe['name']}: {probe['what']}")
    return lines


def totals_notes(data: dict) -> list:
    """Totals of the file other than the fees, against what the coins say. Notes, not refusals."""
    after = unspent_after_each_step(data)
    locked = [sum(coin["value"] for coin in coins.values() if coin["role"] == "covenant") for coins in after]
    deposits = sum(o["value"] for step in data["steps"] for o in step["outputs"] if o["role"] == "deposit")
    change = sum(coin["value"] for coin in after[-1].values() if coin["role"] == "change")
    mine = {"locked_at_peak": max(locked), "locked_at_the_end": locked[-1], "deposits_returned": deposits, "change_at_the_end": change}
    return [
        f"note: totals.{name} is {data['totals'][name]} in the file; counted from the coins it is {value}"
        for name, value in mine.items()
        if data["totals"][name] != value
    ]


def check_offline(data, addresses: dict, harness_folder: str | None) -> tuple:
    """All offline checks. Prints one line per check and every refusal.

    Returns (the refusals, whether the locks were recomputed). A file that
    lacks a field, or has one of the wrong kind, is refused on that alone:
    the other checks are not run on it.
    """
    problems = check_shape(data)
    if problems:
        say("check a  shape of the file              : REFUSED, the other checks were not run")
        for problem in problems:
            say(f"REFUSED  {problem}")
        return problems, False
    locks, locks_done, locks_checked = check_locks(data, harness_folder)
    sections = [
        ("a  format, network, limits, gates", check_basics(data), None, True),
        ("b  parties and their addresses", check_parties(data, addresses), None, True),
        ("c  transaction ids rebuilt by the SDK", check_rebuild(data), None, True),
        ("d  linkage of the coins", check_linkage(data), None, True),
        ("e  fees", check_money(data), None, True),
        ("f  outputs go to the contracts and the parties", check_outputs(data), None, True),
        ("g  covenant id", *check_covenant_id(data), True),
        ("h  locks from states", locks, locks_done, locks_checked),
    ]
    for title, found, done, checked in sections:
        verdict = f"REFUSED ({len(found)})" if found else "ok" if checked else "NOT CHECKED"
        if done and done.startswith("NOT CHECKED"):
            done = done.removeprefix("NOT CHECKED").lstrip(": ") if verdict == "NOT CHECKED" else done
        say(f"check {title:<47}: {verdict}{' - ' + done if done else ''}")
        problems += found
    for problem in problems:
        say(f"REFUSED  {problem}")
    if not problems:
        say("check i  summary")
        for line in summary_lines(data):
            say(f"  {line}")
        for note in totals_notes(data):
            say(f"  {note}")
    return problems, locks_checked


def no_repeated_keys(pairs: list) -> dict:
    """For the JSON reader: an object that names a key twice is refused, not read with the last one winning."""
    found: dict = {}
    for key, value in pairs:
        if key in found:
            raise ValueError(f"the key {key!r} is there twice in one object")
        found[key] = value
    return found


def read_chain(path: str) -> tuple:
    """(the chain file as data, the SHA-256 of the bytes it was read from)."""
    try:
        raw = Path(path).read_bytes()
        return json.loads(raw, object_pairs_hook=no_repeated_keys), hashlib.sha256(raw).hexdigest()
    except OSError as error:
        raise Stop(EXIT_CHECK, f"Cannot read {path}: {error}") from None
    except ValueError as error:
        raise Stop(EXIT_CHECK, f"{path} does not read as JSON: {error}") from None


def party_addresses(pairs: list) -> dict:
    addresses = {}
    for pair in pairs:
        name, mark, address = pair.partition("=")
        if not mark or not name or not address:
            raise Stop(EXIT_CHECK, f"--party wants NAME=ADDRESS, got {pair!r}")
        if name in addresses:
            raise Stop(EXIT_CHECK, f"--party names {name!r} twice")
        if not address.startswith(ADDRESS_PREFIX):
            raise Stop(EXIT_CHECK, f"Refusing: the address of {name!r} does not start with {ADDRESS_PREFIX}")
        addresses[name] = address
    return addresses


# --------------------------------------------------------------------------
# Network: reading
# --------------------------------------------------------------------------


async def quietly_disconnect(client) -> None:
    try:
        await client.disconnect()
    except Exception:
        pass


async def check_node(client) -> dict:
    """Refuse a node that is not a synced testnet-10 node.

    Asked after every connection - the first one and each reconnect, which may
    land on another node - and right before every submission.
    """
    info = await asyncio.wait_for(client.get_server_info(), timeout=Timing.answer_timeout)
    if info.get("networkId") != NETWORK_ID:
        await quietly_disconnect(client)
        raise WrongNode(f"Refusing: the node reports network {info.get('networkId')!r}, not {NETWORK_ID!r}.")
    if not info.get("isSynced"):
        await quietly_disconnect(client)
        raise WrongNode("Refusing: the node is not synced.")
    return info


async def connect():
    """A checked connection: (client, what the node said about itself)."""
    client = RpcClient(resolver=Resolver(), network_id=NETWORK_ID)
    await asyncio.wait_for(client.connect(), timeout=Timing.connect_timeout)
    info = await check_node(client)
    return client, info


async def open_node():
    """`connect`, with a failure to connect told in one line."""
    try:
        return await connect()
    except Stop:
        raise
    except Exception as error:
        raise Stop(EXIT_CHECK, f"Cannot connect to a node ({str(error) or type(error).__name__}). Nothing was sent.") from None


async def reading(work):
    """Await a read of the network; a read that fails for good ends the program in one line."""
    try:
        return await work
    except Stop:
        raise
    except Exception as error:
        raise Stop(EXIT_CHECK, f"The node could not be read ({str(error) or type(error).__name__}). Nothing was sent.") from None


async def utxos_at(client, address: str) -> list:
    """UTXOs at `address`. Public nodes drop connections now and then: retry a few times.

    After a failed read the program reconnects, and reads again only once the
    node it reached has said what it is. A reconnect that fails, or a node
    that does not answer that question, counts as one more failed attempt.
    """
    last_error = None
    checked = True  # the connection handed in was checked when it was made
    for attempt in range(Timing.read_attempts):
        try:
            if not checked:
                await asyncio.wait_for(client.connect(), timeout=Timing.connect_timeout)
                info = await check_node(client)  # a wrong or unsynced node stops the program here
                checked = True
                say(f"via     : {getattr(client, 'url', '?')}, node version {info.get('serverVersion')} (after a reconnect)")
            question = client.get_utxos_by_addresses({"addresses": [address]})
            result = await asyncio.wait_for(question, timeout=Timing.answer_timeout)
            return list(result["entries"])
        except WrongNode:
            raise
        except Exception as error:
            last_error = error
            checked = False
            if Timing.read_pause_seconds:
                await asyncio.sleep(Timing.read_pause_seconds + attempt)
    raise last_error


def entry_key(entry: dict) -> tuple:
    return (entry["outpoint"]["transactionId"], entry["outpoint"]["index"])


def entry_script(entry: dict) -> tuple:
    """(version, script hex) of a node's entry. A node gives 4 hex characters of version and then the script."""
    script = entry["utxoEntry"]["scriptPublicKey"]
    if isinstance(script, str):
        return int(script[:4], 16), script[4:]
    if isinstance(script, dict):
        return script["version"], script["script"]
    return script.version, script.script


def entry_shown(entry: dict) -> dict:
    """An entry as it goes into the record."""
    version, script = entry_script(entry)
    return {
        "outpoint": outpoint_text(entry_key(entry)),
        "amount": entry["utxoEntry"]["amount"],
        "covenant_id": entry["utxoEntry"].get("covenantId"),
        "script_public_key_version": version,
        "script_public_key": script,
        "block_daa_score": entry["utxoEntry"].get("blockDaaScore"),
    }


def entry_differences(entry: dict, coin: dict) -> list:
    """Where a node's entry differs from the coin the file expects at that outpoint."""
    found = []
    if entry["utxoEntry"]["amount"] != coin["value"]:
        found.append(f"amount {entry['utxoEntry']['amount']} instead of {coin['value']}")
    if (entry["utxoEntry"].get("covenantId") or None) != coin["covenant_id"]:
        found.append(f"covenant id {entry['utxoEntry'].get('covenantId')} instead of {coin['covenant_id']}")
    if entry_script(entry) != (coin["version"], coin["script"]):
        found.append("another script")
    return found


async def find_coins(client, coins: list) -> tuple:
    """Look for `coins` on chain, each at the address of its script.

    Returns (entries, wrong): `entries[i]` is the node's entry of `coins[i]`
    or None when it is not there; `wrong` lists coins found at their outpoint
    with another amount, covenant id or script, and coins a node lists twice.
    """
    by_address: dict = {}
    repeated: set = set()
    entries, wrong = [], []
    for coin in coins:
        address = address_of_script(coin["version"], coin["script"])
        if address not in by_address:
            listed = await utxos_at(client, address)
            by_address[address] = {entry_key(entry): entry for entry in listed}
            keys = [entry_key(entry) for entry in listed]
            repeated |= {key for key in keys if keys.count(key) > 1}
        entry = by_address[address].get(coin["key"])
        if entry is not None:
            differences = entry_differences(entry, coin)
            if coin["key"] in repeated:
                differences.append("more than one entry for this outpoint in the node's answer")
            if differences:
                wrong.append(f"{coin['label']} ({outpoint_text(coin['key'])}) is on chain with {', '.join(differences)}")
        entries.append(entry)
    return entries, wrong


async def balances(client, addresses: dict) -> dict:
    """What sits at each party's address: {name: {"address", "sompi", "coins"}}."""
    result = {}
    for name, address in addresses.items():
        entries = await utxos_at(client, address)
        result[name] = {
            "address": address,
            "sompi": sum(entry["utxoEntry"]["amount"] for entry in entries),
            "coins": len(entries),
        }
    return result


def say_balances(title: str, found: dict) -> None:
    for name, at in found.items():
        say(f"{title}: {name:<8} {kas(at['sompi'])} KAS in {at['coins']} coin(s) at {at['address']}")


async def fee_estimate(client) -> dict:
    return (await asyncio.wait_for(client.get_fee_estimate(), timeout=Timing.answer_timeout))["estimate"]


def say_estimate(estimate: dict) -> None:
    say(f"estimate: priority bucket {estimate.get('priorityBucket')}")
    say(f"estimate: normal buckets  {estimate.get('normalBuckets')}")
    say(f"estimate: low buckets     {estimate.get('lowBuckets')}")


class Picture:
    """Which coins of the chain are on chain right now."""

    def __init__(self, data: dict, visible: dict, wrong: list):
        self.visible = visible  # outpoint -> the node's entry, coins of the chain only
        self.wrong = wrong
        steps = data["steps"]
        self.after = unspent_after_each_step(data)
        made = {coin["key"] for step in steps for coin in output_coins(step)}
        seen = set(visible) & (made | {funding_coin(data)["key"]})
        # A step is proven to be on chain when one of its outputs is there, or a proven later step spends one.
        self.proven = [False] * len(steps)
        for position in range(len(steps) - 1, -1, -1):
            own = {coin["key"] for coin in output_coins(steps[position])}
            spent_later = any(
                self.proven[later] and own & set(spent_keys(steps[later])) for later in range(position + 1, len(steps))
            )
            self.proven[position] = bool(own & seen) or spent_later
        # How many steps are on chain, if what is visible is exactly what is unspent after that many.
        self.prefix = next((count for count, coins in enumerate(self.after) if set(coins) == seen), None)
        self.probe_outputs = [
            coin for probe in data["probes"] for coin in output_coins(probe) if coin["key"] in visible and coin["key"] not in made
        ]


async def read_picture(client, data: dict) -> Picture:
    coins = [funding_coin(data)]
    for group in ("steps", "probes"):
        for transaction in data[group]:
            coins += output_coins(transaction)
    unique = list({coin["key"]: coin for coin in coins}.values())
    entries, wrong = await find_coins(client, unique)
    visible = {coin["key"]: entry for coin, entry in zip(unique, entries) if entry is not None}
    return Picture(data, visible, wrong)


def picture_lines(data: dict, picture: Picture) -> tuple:
    """(lines for a reader, problems) about what is on chain."""
    lines, problems = [], list(picture.wrong)
    steps = data["steps"]
    funding = funding_coin(data)
    for coin in picture.probe_outputs:
        problems.append(f"FORBIDDEN MOVE on chain: {coin['label']} ({outpoint_text(coin['key'])}) is visible")
    if not picture.visible:
        problems.append(
            "neither the funding coin nor any coin of this chain is on chain: the funding coin is not at its owner's "
            f"address ({outpoint_text(funding['key'])}), and no output of a step is visible"
        )
    elif picture.prefix is None:
        proven = [steps[i]["name"] for i in range(len(steps)) if picture.proven[i]]
        problems.append(
            "the coins visible on chain are not what is unspent after any number of steps of this file "
            f"(funding coin visible: {funding['key'] in picture.visible}; steps with visible traces: {proven or 'none'}). "
            "A transaction that is still on its way gives the same picture: look again in a minute."
        )
    elif picture.prefix == 0:
        lines.append("on chain: the funding coin is at its owner's address, unspent, with the stated value and script; no step is on chain")
    else:
        done = ", ".join(repr(step["name"]) for step in steps[: picture.prefix])
        lines.append(f"on chain: the first {picture.prefix} of {len(steps)} steps are on chain ({done}); the funding coin is spent")
    return lines, problems


async def check_online(client, data: dict) -> tuple:
    """The read-only network checks of `check --online`. Returns (problems, picture)."""
    estimate = await fee_estimate(client)
    say_estimate(estimate)
    suggested = max(MIN_FEERATE, math.ceil(estimate["priorityBucket"]["feerate"]))
    say(f"feerate : the file was built at {data['feerate']} sompi per gram; the node's priority estimate now gives {suggested}")
    if suggested > data["feerate"]:
        say("feerate : NOTE - the node now asks for more than the file pays; a step may wait or be refused for its fee")
    picture = await read_picture(client, data)
    lines, problems = picture_lines(data, picture)
    if not problems and picture.prefix == 0:
        # Nothing is on chain yet. The first step is built exactly as `send` would build it, with the
        # node's own entry of the funding coin on its input, and not submitted: what does not build
        # is found out here, before anything is sent.
        first = data["steps"][0]
        try:
            to_submit(first, [picture.visible[key] for key in spent_keys(first)])
            lines.append(f"built   : the first step ({first['name']!r}) builds for sending from the node's own entry of the funding coin; not submitted")
        except Stop as stop:
            problems.append(stop.message)
        except Exception as error:
            problems.append(
                f"the first step ({first['name']!r}) could not be built for sending from the node's own entry of the "
                f"funding coin ({type(error).__name__}: {error})"
            )
    for line in lines:
        say(line)
    for problem in problems:
        say(f"REFUSED  {problem}")
    return problems, picture


# --------------------------------------------------------------------------
# Network: submitting
# --------------------------------------------------------------------------


async def submit(client, built: Transaction) -> tuple:
    """Return (accepted, the id the node returns or the node's refusal).

    Only the node's own answer counts as a refusal. Any other failure - a
    dropped connection, a timeout - raises `NoAnswer`: the transaction may
    have been accepted all the same. Right before the transaction is handed
    over the node is asked what it is: the SDK's client reconnects by itself
    and may then be talking to another node than the one that was asked last.
    """
    try:
        await check_node(client)
    except WrongNode as wrong:
        raise Stop(EXIT_NODE, f"Not sent: {wrong.message}") from wrong
    except Exception as error:
        raise Stop(EXIT_NODE, f"Not sent: the node did not say what it is ({str(error) or type(error).__name__}).") from error
    try:
        handed = client.submit_transaction({"transaction": built, "allowOrphan": False})
        result = await asyncio.wait_for(handed, timeout=Timing.answer_timeout)
        return True, str(result["transactionId"])
    except Exception as error:  # the node's refusal arrives as an exception too
        reason = str(error) or type(error).__name__
        if REFUSAL_MARK in reason:
            return False, reason
        raise NoAnswer(reason) from error


async def wait_for_coins(client, coins: list, polls: int) -> tuple:
    """Look for `coins` until all are there or `polls` looks are used up. Returns (entries, wrong, seconds)."""
    started = time.monotonic()
    limit = polls * Timing.poll_seconds  # a look takes time too: the clock ends the wait as well as the count
    entries, wrong = [None] * len(coins), []
    for look in range(polls):
        entries, wrong = await find_coins(client, coins)
        if wrong or all(entry is not None for entry in entries):
            break
        if look == polls - 1 or time.monotonic() - started >= limit:
            break
        await asyncio.sleep(Timing.poll_seconds)
    return entries, wrong, round(time.monotonic() - started, 1)


class Record:
    """The record of a run: one JSON object per line, written as things happen.

    Events go in through `note`: a line that cannot be written is printed
    instead and the record is marked broken; nothing more is submitted then.
    """

    def __init__(self, folder: Path, url: str, version: str):
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self.path = folder / f"run-{stamp}.jsonl"
        self.url, self.version = url, version
        self.broken = False

    def write(self, what: str, **fields) -> None:
        event = {"time_utc": utc_now(), "node": self.url, "node_version": self.version, "what": what, **fields}
        with open(self.path, "a", encoding="utf-8", newline="\n") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")
            file.flush()
            os.fsync(file.fileno())

    def must_be_whole(self, before: str) -> None:
        if self.broken:
            raise Stop(EXIT_RECORD, f"STOP before {before}: the record could not be written. Nothing more was submitted.")


def note(record: Record, what: str, **fields) -> None:
    """Write an event into the record. One that cannot be written goes on screen instead, and the record is marked broken."""
    try:
        record.write(what, **fields)
    except Exception as error:
        record.broken = True
        reason = getattr(error, "strerror", None) or str(error)
        shown = json.dumps({"what": what, **fields}, ensure_ascii=False, default=str)
        say(f"RECORD NOT WRITTEN ({type(error).__name__}: {reason}): {shown}")


def shown_path(path: Path) -> str:
    """A path for the screen: relative to the current folder when it lies under it, else its name alone."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return path.name


WATCHED = ("step accepted", "step refused", "step no answer", "probe accepted", "probe already with a node", "probe no answer")


STEP_UNKNOWN = "step handed over, outcome unknown"
PROBE_UNKNOWN = "probe handed over, outcome unknown"


def earlier_events(folder: Path) -> dict:
    """What earlier runs recorded in `folder`: for each watched event, the ids of the transactions it was written for.

    Two more sets hold the hand-overs whose outcome never reached the record
    (the program was interrupted or killed, or the record broke): the last
    line about them is "submitting" or "interrupted".
    """
    found = {what: set() for what in WATCHED + (STEP_UNKNOWN, PROBE_UNKNOWN)}
    if not folder.is_dir():
        return found
    for path in sorted(folder.glob("run-*.jsonl")):  # the names carry the time: oldest first
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or not isinstance(event.get("transaction_id"), str):
                continue
            what, txid = event.get("what"), event["transaction_id"]
            if what in WATCHED:
                found[what].add(txid)
            # A hand-over is open from "submitting" (or an interrupt) until its outcome is written.
            if what in ("step submitting", "step interrupted"):
                found[STEP_UNKNOWN].add(txid)
            elif what in ("step accepted", "step refused", "step no answer"):
                found[STEP_UNKNOWN].discard(txid)
            elif what in ("probe submitting", "probe interrupted"):
                found[PROBE_UNKNOWN].add(txid)
            elif isinstance(what, str) and what.startswith("probe refused"):
                found[PROBE_UNKNOWN].discard(txid)
    return found


def inputs_shown(transaction: dict) -> list:
    """The inputs as they go into the record: a signature script by its first 16 characters and its length."""
    return [
        {
            "outpoint": outpoint_text((tx_input["transaction_id"], tx_input["index"])),
            "compute_budget": tx_input["compute_budget"],
            "signature_script_starts": tx_input["signature_script"][:16],
            "signature_script_bytes": len(tx_input["signature_script"]) // 2,
        }
        for tx_input in transaction["inputs"]
    ]


def to_submit(transaction: dict, entries: list) -> Transaction:
    """The transaction with the node's own entries on its inputs, checked once more against the file."""
    built = build_transaction(transaction, entries)
    wrong = differences_outside_the_id(built, transaction)
    if built.id != transaction["transaction_id"]:
        wrong.append(f"its id is {built.id}, the file says {transaction['transaction_id']}")
    if wrong:
        raise Stop(EXIT_INCONSISTENT, f"STOP before {transaction['name']!r}: built for sending it differs from the file: {'; '.join(wrong)}")
    return built


def refusal_kind(text: str) -> str:
    lowered = text.lower()
    return "script" if any(mark in lowered for mark in SCRIPT_FAILURE_MARKS) else "other"


async def send_step(client, record: Record, data: dict, position: int, picture: Picture, recorded: set, again: dict) -> str:
    """Send one step, or see that it is on chain already.

    Returns "sent" when it was handed over (now or in an earlier run) and its
    outputs were seen, "found" when it was on chain already; raises Stop
    otherwise. `again` names the steps an earlier run stopped at, which the
    operator has decided to hand over once more.
    """
    step = data["steps"][position]
    name, txid = step["name"], step["transaction_id"]
    title = f"step {position + 1:>2} {name!r}"
    inputs = [spent_coin(tx_input) for tx_input in step["inputs"]]
    outputs = output_coins(step)
    entries, wrong = await find_coins(client, inputs)
    if wrong:
        note(record, "stopped", step=name, transaction_id=txid, reason="inputs differ on chain", details=wrong)
        raise Stop(EXIT_INCONSISTENT, f"STOP at {title}: {'; '.join(wrong)}. Nothing was submitted.")
    missing = [coin for coin, entry in zip(inputs, entries) if entry is None]
    if missing:
        own, own_wrong = await find_coins(client, outputs)
        if own_wrong:
            note(record, "stopped", step=name, transaction_id=txid, reason="outputs differ on chain", details=own_wrong)
            raise Stop(EXIT_INCONSISTENT, f"STOP at {title}: {'; '.join(own_wrong)}. Nothing was submitted.")
        seen_own = [entry for entry in own if entry is not None]
        why = None
        if seen_own:
            why = f"{len(seen_own)} of its {len(outputs)} outputs are visible"
        elif picture.proven[position]:
            why = "a later step that spends its outputs is on chain"
        if why is None:
            found = [outpoint_text(coin["key"]) for coin, entry in zip(inputs, entries) if entry is not None]
            lacking = [f"{outpoint_text(coin['key'])} ({coin['label']})" for coin in missing]
            note(record, "stopped", step=name, transaction_id=txid, reason="inputs not on chain", found=found, missing=lacking)
            raise Stop(
                EXIT_INCONSISTENT,
                f"STOP at {title}: not all of its inputs are on chain, and nothing on chain shows that it was sent. "
                f"Found: {found or 'none'}. Not found: {lacking}. None of its outputs is visible. Nothing was submitted.",
            )
        say(f"{title}: already done, not sent ({why})")
        note(record, "step already done", step=name, transaction_id=txid, reason=why, entries_seen=[entry_shown(e) for e in seen_own])
        return "found"

    polls = Timing.seen_polls
    if txid in recorded:
        # Handed over and accepted in an earlier run, but its outputs were not seen then. Never sent twice.
        say(f"{title}: an earlier run recorded it as accepted; not sent again, looking for its outputs")
        note(record, "step accepted earlier, waiting", step=name, transaction_id=txid)
    else:
        built = to_submit(step, entries)
        say(f"{title}: submitting {txid} (fee {kas(step['fee'])} KAS)")
        if txid in again:
            say(f"{title}: HANDED OVER AGAIN by the operator's decision (--again-after-a-stop); an earlier run recorded {again[txid]!r}")
        note(
            record,
            "step submitting", step=name, transaction_id=txid, fee=step["fee"], mass=step["mass"], inputs=inputs_shown(step),
            again_by_the_operator_after=again.get(txid),
        )
        record.must_be_whole(title)
        try:
            accepted, answer = await submit(client, built)
        except asyncio.CancelledError:
            # An interrupt landed on the hand-over. Recorded, and never gone on from: the run ends here.
            INTERRUPTED.update(what=title, transaction_id=txid)
            note(record, "step interrupted", step=name, transaction_id=txid)
            raise
        except NoAnswer as lost:
            say(f"{title}: NO ANSWER ({lost}); looking for its outputs")
            note(record, "step answer lost", step=name, transaction_id=txid, answer=str(lost))
            try:
                found, found_wrong, seconds = await wait_for_coins(client, outputs, Timing.lost_polls)
            except Exception as error:
                reason = getattr(error, "message", None) or str(error) or type(error).__name__
                found, found_wrong, seconds = [None] * len(outputs), [], None
                say(f"{title}: the look-up then stopped ({reason})")
            if not any(entry is not None for entry in found):
                note(record, "step no answer", step=name, transaction_id=txid, answer=str(lost), seconds_looked=seconds)
                raise Stop(
                    EXIT_NO_ANSWER,
                    f"STOP at {title}: NO ANSWER from the node ({lost}), and its outputs did not show up. "
                    f"Transaction {txid} may have been accepted all the same. Run `status` later. A later `send` "
                    "with the same --record folder goes on by itself only if this step is then on chain; otherwise "
                    "it hands the step over again only with --again-after-a-stop.",
                ) from None
            say(f"{title}: its outputs are on chain, so the node had accepted it")
            note(record, "step accepted", step=name, transaction_id=txid, answer=None, how="outputs seen after a lost answer")
        else:
            if not accepted:
                say(f"{title}: REFUSED by the node")
                say(f"reason  : {answer}")
                if "already" in answer.lower():
                    say("hint    : the node seems to have this transaction already; run `status`, and `send` again once its outputs are visible")
                note(record, "step refused", step=name, transaction_id=txid, answer=answer)
                raise Stop(
                    EXIT_REFUSED,
                    f"STOP at {title}: the node refused it. Nothing after it was submitted. A later `send` with the "
                    "same --record folder does not hand it over again unless --again-after-a-stop is given.",
                )
            if answer != txid:
                note(record, "stopped", step=name, transaction_id=txid, reason="the node returned another id", answer=answer)
                raise Stop(EXIT_INCONSISTENT, f"STOP at {title}: the node accepted it under the id {answer}, the file expects {txid}.")
            say(f"{title}: ACCEPTED {answer}")
            note(record, "step accepted", step=name, transaction_id=txid, answer=answer, how="the node's answer")

    try:
        found, found_wrong, seconds = await wait_for_coins(client, outputs, polls)
    except Exception as error:
        reason = getattr(error, "message", None) or str(error) or type(error).__name__
        note(record, "step not seen", step=name, transaction_id=txid, reason=f"the look-up stopped: {reason}")
        raise Stop(EXIT_NOT_SEEN, f"STOP at {title}: submitted, not seen - the look-up stopped ({reason}). Not submitted again. Run `status` later.") from None
    if found_wrong:
        note(record, "stopped", step=name, transaction_id=txid, reason="outputs differ on chain", details=found_wrong)
        raise Stop(EXIT_INCONSISTENT, f"STOP at {title}: {'; '.join(found_wrong)}")
    if not all(entry is not None for entry in found):
        lacking = [outpoint_text(coin["key"]) for coin, entry in zip(outputs, found) if entry is None]
        note(record, "step not seen", step=name, transaction_id=txid, seconds_looked=seconds, missing=lacking)
        raise Stop(
            EXIT_NOT_SEEN,
            f"STOP at {title}: submitted, not seen - after {seconds} s these outputs are not visible: {lacking}. "
            "Not submitted again. Run `status` later; `send` with the same --record folder waits for them without sending "
            "twice. If the node has dropped the transaction, a run with a new --record folder submits it again.",
        )
    say(f"{title}: all {len(outputs)} outputs seen after {seconds} s, as expected")
    note(record, "step seen", step=name, transaction_id=txid, seconds_until_seen=seconds, entries_seen=[entry_shown(e) for e in found])
    return "sent"


async def send_probe(client, record: Record, data: dict, position: int) -> str:
    """Send one forbidden move. Returns how it was refused ("script" or "other"); raises Stop on anything else."""
    probe = data["probes"][position]
    name, txid = probe["name"], probe["transaction_id"]
    title = f"probe {position + 1} {name!r}"
    inputs = [spent_coin(tx_input) for tx_input in probe["inputs"]]
    outputs = output_coins(probe)
    entries, wrong = await find_coins(client, inputs)
    missing = [f"{outpoint_text(coin['key'])} ({coin['label']})" for coin, entry in zip(inputs, entries) if entry is None]
    if wrong or missing:
        note(record, "stopped", probe=name, transaction_id=txid, reason="inputs not on chain as expected", missing=missing, details=wrong)
        raise Stop(
            EXIT_INCONSISTENT,
            f"STOP at {title}: its inputs are not on chain as expected (not found: {missing or 'none'}; differing: {wrong or 'none'}). "
            "A refusal would prove nothing, so it was not submitted.",
        )
    built = to_submit(probe, entries)
    say(f"{title}: submitting {txid}, expecting a refusal")
    note(record, "probe submitting", probe=name, transaction_id=txid, inputs=inputs_shown(probe))
    record.must_be_whole(title)
    try:
        accepted, answer = await submit(client, built)
    except asyncio.CancelledError:
        INTERRUPTED.update(what=title, transaction_id=txid)
        note(record, "probe interrupted", probe=name, transaction_id=txid)
        raise
    except NoAnswer as lost:
        say(f"{title}: NO ANSWER ({lost}); looking for its outputs")
        try:
            found, _, seconds = await wait_for_coins(client, outputs, Timing.lost_polls)
        except Exception as error:
            reason = getattr(error, "message", None) or str(error) or type(error).__name__
            found, seconds = [None] * len(outputs), None
            say(f"{title}: the look-up then stopped ({reason})")
        if any(entry is not None for entry in found):
            say("FORBIDDEN MOVE ACCEPTED")
            note(record, "probe accepted", probe=name, transaction_id=txid, answer=None, how="outputs seen after a lost answer",
                         entries_seen=[entry_shown(e) for e in found if e is not None])
            raise Stop(EXIT_FORBIDDEN_ACCEPTED, f"STOP at {title}: FORBIDDEN MOVE ACCEPTED - its outputs are on chain. No further probe was sent in this run, and no later run with this record sends one.") from None
        note(record, "probe no answer", probe=name, transaction_id=txid, answer=str(lost), seconds_looked=seconds)
        raise Stop(
            EXIT_NO_ANSWER,
            f"STOP at {title}: NO ANSWER from the node ({lost}), and its outputs did not show up. Run `status` later.",
        ) from None
    if accepted:
        say("FORBIDDEN MOVE ACCEPTED")
        note(record, "probe accepted", probe=name, transaction_id=txid, answer=answer, how="the node's answer")
        raise Stop(EXIT_FORBIDDEN_ACCEPTED, f"STOP at {title}: FORBIDDEN MOVE ACCEPTED by the node as {answer}. No further probe was sent in this run, and no later run with this record sends one.")
    if "already" in answer.lower():
        # Not a refusal of the move: the node holds this transaction, or another one that spends the same coin.
        say("FORBIDDEN MOVE MAY BE WITH A NODE")
        say(f"reason  : {answer}")
        note(record, "probe already with a node", probe=name, transaction_id=txid, answer=answer)
        raise Stop(
            EXIT_FORBIDDEN_ACCEPTED,
            f"STOP at {title}: the node answers that it already has this transaction or one that spends the same coin: "
            "the probe is in a node's mempool or on chain. No further probe was sent. Look with `status`.",
        )
    kind = refusal_kind(answer)
    if kind == "script":
        say(f"{title}: REFUSED, by a script as far as the text tells")
        note(record, "probe refused", probe=name, transaction_id=txid, answer=answer, kind="script failure")
    else:
        say(f"{title}: REFUSED FOR ANOTHER REASON - not the refusal this probe was made for")
        note(record, "probe refused for another reason", probe=name, transaction_id=txid, answer=answer, kind="something else")
    say(f"reason  : {answer}")
    return kind


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


async def cmd_prepare(args) -> int:
    address = args.issuer_address
    if not address.startswith(ADDRESS_PREFIX):
        raise Stop(EXIT_CHECK, f"Refusing: the issuer's address does not start with {ADDRESS_PREFIX}")
    try:
        issuer_script = pay_to_address_script(Address(address))
    except Exception as error:
        raise Stop(EXIT_CHECK, f"The issuer's address does not read as an address ({error}).") from None
    funding_value = round(args.funding_kas * SOMPI_PER_KAS)
    if not 0 < funding_value <= MAX_FUNDING:
        raise Stop(EXIT_CHECK, f"Refusing: the funding coin must hold more than 0 and at most {kas(MAX_FUNDING)} KAS.")
    if args.feerate is not None and args.feerate < MIN_FEERATE:
        raise Stop(EXIT_CHECK, f"Refusing: --feerate must be at least {MIN_FEERATE} sompi per gram.")
    out = Path(args.out)
    if out.exists():
        raise Stop(EXIT_CHECK, f"Refusing to overwrite {out}.")
    client, info = await open_node()
    try:
        say(f"via     : {client.url}, node version {info.get('serverVersion')}")
        estimate = await reading(fee_estimate(client))
        say_estimate(estimate)
        if args.feerate is not None:
            feerate = args.feerate
            say(f"feerate : {feerate} sompi per gram (given on the command line)")
        else:
            feerate = max(MIN_FEERATE, math.ceil(estimate["priorityBucket"]["feerate"]))
            say(f"feerate : {feerate} sompi per gram (the node's priority estimate, rounded up, at least {MIN_FEERATE})")
        entries = await reading(utxos_at(client, address))
        fitting = [e for e in entries if not e["utxoEntry"].get("covenantId") and e["utxoEntry"]["amount"] == funding_value]
        if len(fitting) != 1:
            say(f"coins at {address}:")
            for entry in entries:
                bound = " (carries a covenant id)" if entry["utxoEntry"].get("covenantId") else ""
                say(f"  {kas(entry['utxoEntry']['amount'])} KAS  {outpoint_text(entry_key(entry))}{bound}")
            raise Stop(
                EXIT_CHECK,
                f"Refusing: {len(fitting)} plain coins of exactly {kas(funding_value)} KAS at the issuer's address; there must be one.",
            )
        coin = fitting[0]
        version, script = entry_script(coin)
        if (version, script) != (issuer_script.version, issuer_script.script):
            raise Stop(EXIT_CHECK, "Refusing: the coin the node returned is not locked to the issuer's address.")
        request = {
            "format": REQUEST_FORMAT,
            "network": NETWORK_ID,
            "read_at_utc": utc_now(),
            "node": client.url,
            "token_name": args.token_name,
            "coin_value": COIN_VALUE,
            "feerate": feerate,
            "fee_cap_total": MAX_TOTAL_FEES,
            "funding": {
                "transaction_id": coin["outpoint"]["transactionId"],
                "index": coin["outpoint"]["index"],
                "value": coin["utxoEntry"]["amount"],
                "script_public_key_version": version,
                "script_public_key": script,
            },
        }
        try:
            with open(out, "x", encoding="utf-8", newline="\n") as file:
                file.write(json.dumps(request, indent=2, ensure_ascii=False) + "\n")
        except FileExistsError:
            raise Stop(EXIT_CHECK, f"Refusing to overwrite {out}.") from None
        say(f"funding : {kas(funding_value)} KAS, {outpoint_text(entry_key(coin))}")
        say(f"written : {out}")
        return EXIT_OK
    finally:
        await quietly_disconnect(client)


async def cmd_check(args) -> int:
    addresses = party_addresses(args.party)
    data, chain_sha256 = read_chain(args.chain)
    say(f"file    : {Path(args.chain).name}, SHA-256 {chain_sha256}")
    problems, locks_checked = check_offline(data, addresses, args.harness)
    if problems:
        say(f"REFUSED: {len(problems)} problem(s). Nothing was sent.")
        return EXIT_CHECK
    without = "" if locks_checked else " EXCEPT check h: the locks were NOT recomputed (no --harness), and `send` does not run without it."
    if not args.online:
        say(f"check: passed (offline).{without} The network was not read.")
        return EXIT_OK
    client, info = await open_node()
    try:
        say(f"via     : {client.url}, node version {info.get('serverVersion')}")
        online, _ = await reading(check_online(client, data))
    finally:
        await quietly_disconnect(client)
    if online:
        say(f"REFUSED: {len(online)} problem(s) on chain. Nothing was sent.")
        return EXIT_CHECK
    say(f"check: passed (offline and online).{without}")
    return EXIT_OK


async def cmd_send(args) -> int:
    if not args.yes_send_to_testnet_10:
        raise Stop(EXIT_CHECK, "Refusing: `send` submits transactions. Say --yes-send-to-testnet-10 to mean it. Nothing was sent.")
    if not args.harness:
        raise Stop(
            EXIT_CHECK,
            "Refusing: `send` needs --harness (or KCC20_HARNESS_DIR). Without it nothing shows that the covenant "
            "outputs are coins of the token's contracts. Nothing was sent.",
        )
    addresses = party_addresses(args.party)
    data, chain_sha256 = read_chain(args.chain)
    say(f"file    : {Path(args.chain).name}, SHA-256 {chain_sha256}")
    problems, locks_checked = check_offline(data, addresses, args.harness)
    if problems or not locks_checked:
        say(f"REFUSED: {len(problems)} problem(s). Nothing was sent.")
        return EXIT_CHECK
    folder = Path(args.record)
    earlier = earlier_events(folder)
    # A probe that an earlier run saw accepted, or lost the answer to, may be with a node. No flag overrides this.
    blocking = (
        ("probe accepted", EXIT_FORBIDDEN_ACCEPTED),
        ("probe already with a node", EXIT_FORBIDDEN_ACCEPTED),
        ("probe no answer", EXIT_NO_ANSWER),
        (PROBE_UNKNOWN, EXIT_NO_ANSWER),
    )
    for what, code in blocking:
        names = [probe["name"] for probe in data["probes"] if probe["transaction_id"] in earlier[what]]
        if names:
            raise Stop(
                code,
                f"Refusing: the record folder holds {what!r} for {names}: a forbidden move may be on its way or on chain. "
                "Look with `status`. No flag overrides this. Nothing was sent.",
            )
    client, info = await open_node()
    try:
        say(f"via     : {client.url}, node version {info.get('serverVersion')}")
        online, picture = await reading(check_online(client, data))
        if online:
            say(f"REFUSED: {len(online)} problem(s) on chain. Nothing was sent.")
            return EXIT_INCONSISTENT
        # A step an earlier run stopped at is not handed over a second time by itself.
        # (One that is on chain by now, or that a later run saw accepted and now only waits for, is not in the way.)
        again = {}
        for position, step in enumerate(data["steps"]):
            txid = step["transaction_id"]
            for what in ("step refused", "step no answer", STEP_UNKNOWN):
                if txid in earlier[what] and not picture.proven[position] and txid not in earlier["step accepted"]:
                    again[txid] = what
        if again and not args.again_after_a_stop:
            stopped = [f"{step['name']!r} ({again[step['transaction_id']]})" for step in data["steps"] if step["transaction_id"] in again]
            raise Stop(
                EXIT_CHECK,
                f"Refusing: an earlier run with this record folder stopped at {', '.join(stopped)}, and that step is not on chain. "
                "It is not handed over a second time by itself (where the outcome is unknown, the earlier hand-over "
                "may or may not have reached the node). Look with `status`; to hand it over again by your own "
                "decision, say --again-after-a-stop. Nothing was sent.",
            )
        try:
            record = Record(folder, client.url, str(info.get("serverVersion")))
        except OSError as error:
            raise Stop(EXIT_CHECK, f"The record folder {folder.name!r} cannot be made ({error.strerror}). Nothing was sent.") from None
        note(
            record,
            "run started",
            chain_file=Path(args.chain).name,
            chain_sha256=chain_sha256,
            program_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            harness_sha256=harness_sha256(args.harness),
            covenant_id=data["covenant_id"],
            token_name=data["token_name"],
            steps=len(data["steps"]),
            probes=len(data["probes"]),
            steps_on_chain_at_start=picture.prefix,
            again_after_a_stop=sorted(again) if again else None,
        )
        if record.broken:
            raise Stop(EXIT_CHECK, "The record cannot be written. Nothing was sent.")
        say(f"record  : {shown_path(record.path)}")
        try:
            before = await balances(client, addresses)
            say_balances("before ", before)
            note(record, "balances before", balances=before)
            done = []
            for position in range(len(data["steps"])):
                done.append(await send_step(client, record, data, position, picture, earlier["step accepted"], again))
            say(f"steps   : {done.count('sent')} handed over and seen on chain, {done.count('found')} found on chain already; {len(done)} in all")
            kinds = []
            for position in range(len(data["probes"])):
                kinds.append(await send_probe(client, record, data, position))
            after = await balances(client, addresses)
            say_balances("after  ", after)
            note(record, "balances after", balances=after)
            other = kinds.count("other")
            note(record, "run finished", steps=len(data["steps"]), probes_refused=len(kinds), refused_for_another_reason=other)
            say(f"finished: {len(data['steps'])} steps on chain; {len(kinds)} probes refused, {other} of them for another reason than a script")
            if record.broken:
                raise Stop(EXIT_RECORD, "STOP: the run went through, but the record could not be written in full: the lines are above.")
            return EXIT_OK
        except Stop as stop:
            # The last line goes on screen first: whatever happens to the record, the stop is told and keeps its code.
            code = EXIT_NODE if isinstance(stop, WrongNode) else stop.code
            message = f"STOP: {stop.message} Nothing more was submitted." if isinstance(stop, WrongNode) else stop.message
            say(message)
            at_stop = None
            if code in (EXIT_REFUSED, EXIT_FORBIDDEN_ACCEPTED, EXIT_INCONSISTENT):
                # The node has just answered: note where the money stands. If it cannot be read now, the stop stands as it is.
                try:
                    at_stop = await balances(client, addresses)
                    say_balances("at stop", at_stop)
                except Exception:
                    at_stop = None
            note(record, "run stopped", exit_code=code, last_words=message, balances=at_stop)
            final = Stop(code, message)
            final.said = True
            raise final from None
        except Exception as error:
            # Reading failed for good (the retries ran out) before a submission of the step at hand.
            reason = f"{type(error).__name__}: {error}"
            message = f"STOP: the node could not be read ({reason}). Nothing more was submitted. Run `status`."
            say(message)
            note(record, "run stopped", exit_code=EXIT_NODE, last_words=message)
            final = Stop(EXIT_NODE, message)
            final.said = True
            raise final from None
    finally:
        await quietly_disconnect(client)


async def cmd_status(args) -> int:
    addresses = party_addresses(args.party)
    data, chain_sha256 = read_chain(args.chain)
    problems = check_shape(data)
    if not problems:
        problems = check_parties(data, addresses) + check_rebuild(data) + check_linkage(data)
    if problems:
        for problem in problems:
            say(f"REFUSED  {problem}")
        say("status: the file does not pass the checks `status` needs; run `check`.")
        return EXIT_CHECK
    client, info = await open_node()
    try:
        say(f"via     : {client.url}, node version {info.get('serverVersion')}")
        picture = await reading(read_picture(client, data))
        lines, wrong = picture_lines(data, picture)
        for position, step in enumerate(data["steps"]):
            coins = output_coins(step)
            visible = [coin for coin in coins if coin["key"] in picture.visible]
            proven = "on chain" if picture.proven[position] else "no trace"
            say(f"step {position + 1:>2} {step['name']!r}: {proven}; {len(visible)} of {len(coins)} outputs unspent")
        for position, probe in enumerate(data["probes"]):
            made = [coin for coin in output_coins(probe) if coin in picture.probe_outputs]
            say(f"probe {position + 1} {probe['name']!r}: {'OUTPUTS VISIBLE - a forbidden move is on chain' if made else 'no trace'}")
        say("coins of the chain that are unspent now:")
        known = {coin["key"]: coin for coin in [funding_coin(data)] + [c for s in data["steps"] for c in output_coins(s)]}
        for key, entry in picture.visible.items():
            coin = known.get(key)
            if coin is None:
                continue
            state = coin["state"] or {}
            what = coin["role"] + (f" to {coin['to']!r}" if coin["to"] else "") + (f" {state.get('contract')}" if state else "")
            say(f"  {kas(entry['utxoEntry']['amount'])} KAS  {outpoint_text(key)}  {what}")
        for line in lines:
            say(line)
        for problem in wrong:
            say(f"NOTE     {problem}")
        say_balances("balance", await reading(balances(client, addresses)))
        return EXIT_OK if not wrong else EXIT_INCONSISTENT
    finally:
        await quietly_disconnect(client)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Stop(EXIT_CHECK, f"{self.format_usage().strip()}\n{self.prog}: {message}")


def parser() -> argparse.ArgumentParser:
    top = Parser(prog="launch_send.py", description="Check a prepared chain of KCC-20 transactions and send it to Kaspa testnet-10.")
    commands = top.add_subparsers(dest="command", required=True, parser_class=Parser)

    prepare = commands.add_parser("prepare", help="read the funding coin and the feerate, write the request (read-only)")
    prepare.add_argument("--issuer-address", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--funding-kas", type=float, default=MAX_FUNDING / SOMPI_PER_KAS)
    prepare.add_argument("--feerate", type=int, default=None)
    prepare.add_argument("--token-name", default="unnamed")

    def with_chain(command):
        command.add_argument("chain")
        command.add_argument("--party", action="append", required=True, metavar="NAME=ADDRESS")

    check = commands.add_parser("check", help="verify the chain file; with --online also read the network")
    with_chain(check)
    check.add_argument("--harness", default=os.environ.get("KCC20_HARNESS_DIR"))
    check.add_argument("--online", action="store_true")

    send = commands.add_parser("send", help="check, then submit the steps and the probes")
    with_chain(send)
    send.add_argument("--harness", default=os.environ.get("KCC20_HARNESS_DIR"))
    send.add_argument("--record", required=True, metavar="DIR")
    send.add_argument("--yes-send-to-testnet-10", action="store_true")
    send.add_argument("--again-after-a-stop", action="store_true")

    status = commands.add_parser("status", help="what of the chain is on chain now (read-only)")
    with_chain(status)
    return top


COMMANDS = {"prepare": cmd_prepare, "check": cmd_check, "send": cmd_send, "status": cmd_status}


def main(argv: list | None = None) -> int:
    INTERRUPTED.clear()
    for stream in (sys.stdout, sys.stderr):
        # A console that cannot show a character of the file's texts must not end a run.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    try:
        args = parser().parse_args(argv)
        return asyncio.run(COMMANDS[args.command](args))
    except Stop as stop:
        if not stop.said:
            say(stop.message)
        return stop.code
    except (KeyboardInterrupt, asyncio.CancelledError):
        if INTERRUPTED:
            say(
                f"Interrupted while {INTERRUPTED['what']}, transaction {INTERRUPTED['transaction_id']}, was being handed "
                "over: it may or may not have reached the node. Nothing more was submitted. Run `status`."
            )
        else:
            say("Interrupted. Nothing was being handed over at that moment. Run `status` before anything else.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
