"""Offline checks of `launch_send.py`: no network, a fake node, no keys.

Run from the folder of `launch_send.py`:

    python -m unittest discover -s tests -v

The chain file under test is `tests/fixture-chain.json`, made by
`tests/make_fixture.py` from a rehearsal plan of the builder. Its transaction
ids are real ids of its fields; its signature scripts are placeholders, so the
fake node below judges nothing: it takes or refuses what it is told to.

`tests/fixture-selftest-955.json` is a chain file written by the builder's own
self-test, with made-up keys. The signature scripts of its covenant spends are
replaced by placeholders of the same length; the signatures of its plain
inputs are the builder's.

`send` does not run without a harness. The tests of `send` hand it a stand-in
that knows the locks of the two fixtures, so they need nothing outside this
folder. The tests that recompute the locks for real need the study's harness
(`kcc20_harness.py`): its folder is taken from the environment variable
KCC20_HARNESS_DIR and from nowhere else; without it those tests are skipped.
"""

import asyncio
import atexit
import collections
import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kaspa import ScriptPublicKey, address_from_script_public_key

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import launch_send as ls  # noqa: E402

FIXTURE = json.loads((HERE / "fixture-chain.json").read_text(encoding="utf-8"))
SELFTEST = json.loads((HERE / "fixture-selftest-955.json").read_text(encoding="utf-8"))
KAS = ls.SOMPI_PER_KAS
STEP_IDS = [step["transaction_id"] for step in FIXTURE["steps"]]
PROBE_IDS = [probe["transaction_id"] for probe in FIXTURE["probes"]]
FOREIGN_KEY_SCRIPT = "20" + "11" * 32 + "ac"

HARNESS = os.environ.get("KCC20_HARNESS_DIR") or ""
HAVE_HARNESS = bool(HARNESS) and (Path(HARNESS) / "kcc20_harness.py").is_file()
NO_HARNESS = "set KCC20_HARNESS_DIR to the folder of kcc20_harness.py to run the checks that recompute the locks"


class StandInHarness:
    """Knows the lock of every state that the fixtures carry, and of no other state."""

    def __init__(self, *chains):
        self.locks = {}
        for chain in chains:
            for transaction in chain["steps"] + chain["probes"]:
                for output in transaction["outputs"]:
                    if output["role"] == "covenant" and output["state"]:
                        self.locks[json.dumps(output["state"], sort_keys=True)] = output["script_public_key"]

    def lock(self, contract: str, state: dict) -> bytes:
        plain = {name: value.hex() if isinstance(value, bytes) else value for name, value in state.items()}
        return bytes.fromhex(self.locks[json.dumps({"contract": contract, **plain}, sort_keys=True)])


STAND_IN = StandInHarness(FIXTURE, SELFTEST)
STAND_IN_FOLDER = Path(tempfile.mkdtemp(prefix="stand-in-harness-"))
(STAND_IN_FOLDER / "kcc20_harness.py").write_text("# a stand-in for the tests of `send`\n", encoding="utf-8")
atexit.register(shutil.rmtree, STAND_IN_FOLDER, True)
REAL_LOAD = ls.load_harness


def load_harness(folder: str):
    return STAND_IN if Path(folder) == STAND_IN_FOLDER else REAL_LOAD(folder)

SCRIPT_REFUSAL = "failed to verify the signature script: script ran, but verification failed"
FEE_REFUSAL = "transaction has 100 fees which is under the required amount of 200"


def address(script: str) -> str:
    return address_from_script_public_key(ScriptPublicKey(0, script), "testnet").to_string()


PARTIES = {name: address(party["script_public_key"]) for name, party in FIXTURE["parties"].items()}
SELFTEST_PARTIES = {name: address(party["script_public_key"]) for name, party in SELFTEST["parties"].items()}


def party_args(parties: dict = PARTIES) -> list:
    return [word for name, at in parties.items() for word in ("--party", f"{name}={at}")]


class FakeNode:
    """Stands in for the RPC client: holds coins by address and does with a submission what it is told.

    `how` maps a transaction id to one of: "accept" (the default for a step:
    its inputs go, its outputs appear), "refuse" (the default for a probe: the
    node's own refusal, of a script), "refuse-fee" (a refusal for another
    reason), "accept-hidden" (taken, but its outputs never show), "other-id"
    (taken, and another id returned), "lost-applied" (taken, the answer is
    lost), "lost" (not taken, no answer). `submitted` are the ids handed over,
    in order; `handed` the transactions as the SDK shows them. `wrong_after`
    makes the node report another network after that many questions about
    itself. `failing_reads` are exceptions the next reads raise.
    """

    def __init__(self, chain: dict = FIXTURE, network: str = ls.NETWORK_ID, synced: bool = True, funded: bool = True):
        self.url = "wss://fake.example"
        self.network, self.synced = network, synced
        self.coins: dict = {}
        self.how: dict = {}
        self.probe_ids = {probe["transaction_id"] for probe in chain["probes"]}
        self.submitted, self.handed = [], []
        self.questions = self.connections = self.reconnects = self.reads = 0
        self.wrong_after = None
        self.failing_reads: list = []
        self.rate = 308.2
        if funded:
            funding = chain["funding"]
            self.put(funding["transaction_id"], funding["index"], funding["value"], funding["script_public_key"])

    def put(self, txid: str, index: int, amount: int, script: str, covenant_id: str | None = None) -> None:
        at = address(script)
        self.coins.setdefault(at, {})[(txid, index)] = {
            "address": at,
            "outpoint": {"transactionId": txid, "index": index},
            "utxoEntry": {
                "amount": amount,
                "scriptPublicKey": "0000" + script,  # as a node gives it: the version, then the script
                "blockDaaScore": 1,
                "isCoinbase": False,
                "covenantId": covenant_id,
            },
        }

    def holds(self, txid: str, index: int) -> bool:
        return any((txid, index) in coins for coins in self.coins.values())

    def apply(self, shown: dict) -> None:
        spent = [(i["previousOutpoint"]["transactionId"], i["previousOutpoint"]["index"]) for i in shown["inputs"]]
        if not all(self.holds(*key) for key in spent):
            raise RuntimeError(f"Rejected transaction {shown['id']}: transaction {shown['id']} is an orphan where orphan is disallowed")
        for coins in self.coins.values():
            for key in spent:
                coins.pop(key, None)
        for number, output in enumerate(shown["outputs"]):
            covenant = (output.get("covenant") or {}).get("covenantId")
            self.put(shown["id"], number, output["value"], output["scriptPublicKey"]["script"], covenant)

    async def connect(self):
        self.reconnects += 1

    async def disconnect(self):
        return None

    async def get_server_info(self):
        self.questions += 1
        network = self.network
        if self.wrong_after is not None and self.questions > self.wrong_after:
            network = "mainnet"
        return {"networkId": network, "isSynced": self.synced, "serverVersion": "0.0.0-fake"}

    async def get_fee_estimate(self):
        bucket = {"feerate": self.rate, "estimatedSeconds": 0.5}
        return {"estimate": {"priorityBucket": bucket, "normalBuckets": [bucket], "lowBuckets": [bucket]}}

    async def get_utxos_by_addresses(self, request):
        self.reads += 1
        if self.failing_reads:
            raise self.failing_reads.pop(0)
        return {"entries": list(self.coins.get(request["addresses"][0], {}).values())}

    async def submit_transaction(self, request):
        assert request["allowOrphan"] is False
        shown = request["transaction"].to_dict()
        txid = shown["id"]
        # The sender hands over each input with the node's own entry of the coin it spends.
        assert all(tx_input["utxo"] is not None for tx_input in shown["inputs"])
        self.submitted.append(txid)
        self.handed.append(shown)
        how = self.how.get(txid, "refuse" if txid in self.probe_ids else "accept")
        if how == "accept":
            self.apply(shown)
            return {"transactionId": txid}
        if how == "accept-hidden":
            return {"transactionId": txid}
        if how == "other-id":
            self.apply(shown)
            return {"transactionId": "ee" * 32}
        if how == "lost-applied":
            self.apply(shown)
            raise ConnectionError("WebSocket is not connected")
        if how == "lost":
            raise ConnectionError("WebSocket is not connected")
        if how == "refuse":
            raise RuntimeError(f"Rejected transaction {txid}: {SCRIPT_REFUSAL}")
        if how == "refuse-fee":
            raise RuntimeError(f"Rejected transaction {txid}: {FEE_REFUSAL}")
        if how == "refuse-already":
            raise RuntimeError(f"Rejected transaction {txid}: transaction {txid} is already in the mempool")
        raise AssertionError(how)


def run(argv: list, node: FakeNode | None = None) -> tuple:
    """Run the program. Returns (exit code, what it printed)."""

    async def fake_connect():
        if node is None:
            raise AssertionError("the network was reached")
        node.connections += 1
        return node, await ls.check_node(node)

    printed = io.StringIO()
    environment = {name: value for name, value in os.environ.items() if name != "KCC20_HARNESS_DIR"}
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
        stack.enter_context(mock.patch.object(ls, "connect", fake_connect))
        stack.enter_context(mock.patch.object(ls, "load_harness", load_harness))
        for name, value in (("poll_seconds", 0), ("seen_polls", 3), ("lost_polls", 3), ("read_pause_seconds", 0)):
            stack.enter_context(mock.patch.object(ls.Timing, name, value))
        stack.enter_context(contextlib.redirect_stdout(printed))
        code = ls.main(argv)
    return code, printed.getvalue()


class Folder(unittest.TestCase):
    """A temporary folder per test, with the chain file in it."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def chain_file(self, chain: dict = FIXTURE) -> str:
        path = self.folder / "chain.json"
        path.write_text(json.dumps(chain), encoding="utf-8")
        return str(path)

    def check(self, chain: dict = FIXTURE, parties: dict = PARTIES, more: tuple = (), node=None) -> tuple:
        return run(["check", self.chain_file(chain), *party_args(parties), *more], node)

    def send(self, node, chain: dict = FIXTURE, flag: bool = True, record: str = "record", harness: bool = True,
             parties: dict = PARTIES, more: tuple = ()) -> tuple:
        argv = ["send", self.chain_file(chain), *party_args(parties), "--record", str(self.folder / record), *more]
        argv += ["--harness", str(STAND_IN_FOLDER)] if harness else []
        return run(argv + (["--yes-send-to-testnet-10"] if flag else []), node)

    def events(self, record: str = "record") -> list:
        lines = []
        for path in sorted((self.folder / record).glob("run-*.jsonl")):
            lines += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        return lines

    def record_text(self, record: str = "record") -> str:
        return "".join(path.read_text(encoding="utf-8") for path in sorted((self.folder / record).glob("run-*.jsonl")))


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------


class Check(Folder):
    def refused(self, change, phrase: str, parties: dict = PARTIES) -> str:
        chain = copy.deepcopy(FIXTURE)
        change(chain)
        code, printed = self.check(chain, parties)
        self.assertEqual(code, ls.EXIT_CHECK, printed)
        self.assertIn(phrase, printed)
        self.assertIn("Nothing was sent", printed)
        return printed

    def test_the_fixture_passes(self):
        code, printed = self.check()
        self.assertEqual(code, 0, printed)
        self.assertNotIn("REFUSED", printed)
        # Without a harness the locks are not recomputed: check h is never "ok" then, and the last line says so.
        self.assertIn("check h  locks from states                           : NOT CHECKED - no --harness given", printed)
        self.assertIn("check: passed (offline). EXCEPT check h: the locks were NOT recomputed (no --harness), and `send` does not run without it.", printed)
        # The summary: who holds what at the end, by the states of the unspent coins.
        self.assertIn("tokens        : alice 13", printed)
        self.assertIn("tokens        : bob 12", printed)
        self.assertIn("derived by the SDK from the first step, 2 output(s)", printed)
        self.assertNotIn("note: totals.", printed)

    def test_an_output_script_changed_to_a_foreign_key(self):
        def change(chain):
            chain["steps"][0]["outputs"][2]["script_public_key"] = FOREIGN_KEY_SCRIPT

        printed = self.refused(change, "but its script is not that party's")
        self.assertIn("id mismatch", printed)  # every failure is listed, not the first one only

    def test_a_change_output_that_names_the_wrong_party(self):
        def change(chain):
            chain["steps"][4]["outputs"][2]["to"] = "alice"

        self.refused(change, "the change is said to go to 'alice', but its script is not that party's")

    def test_a_deposit_to_somebody_who_is_not_a_party(self):
        def change(chain):
            chain["steps"][7]["outputs"][1]["to"] = "mallory"

        self.refused(change, "goes to 'mallory', who is not a party")

    def test_fees_above_the_cap_of_the_file(self):
        def change(chain):
            chain["fee_cap_total"] = chain["totals"]["fees"] - 1

        self.refused(change, "above the cap of the file")

    def test_fees_above_the_hard_limit(self):
        def change(chain):
            chain["steps"][1]["fee"] += 16 * KAS
            chain["totals"]["fees"] += 16 * KAS
            chain["fee_cap_total"] = 100 * KAS

        printed = self.refused(change, "above the hard limit of 15.00000000 KAS")
        self.assertIn("the file says the fee is", printed)  # and the fee no longer is what the coins say

    def test_a_probe_whose_fee_would_take_the_run_over_the_hard_limit(self):
        def change(chain):
            # The probe's own numbers agree with each other; only the limit is in the way.
            probe = chain["probes"][2]
            probe["fee"] += 15 * KAS
            probe["outputs"][2]["value"] -= 15 * KAS

        printed = self.refused(change, "the fees of the steps and of the dearest probe sum to 15.14737690 KAS")
        self.assertNotIn("the file says the fee is", printed)

    def test_a_fee_below_its_floor(self):
        def change(chain):
            chain["steps"][2]["fee_floor"] = chain["steps"][2]["fee"] + 1

        self.refused(change, "is below its floor")

    def test_an_input_that_spends_an_output_that_does_not_exist(self):
        def change(chain):
            chain["steps"][3]["inputs"][0]["spends"]["from"]["output"] = 9

        self.refused(change, "output 9 of the step '01 launch' does not exist")

    def test_an_input_that_spends_an_output_of_a_later_step(self):
        def change(chain):
            chain["steps"][3]["inputs"][0]["spends"]["from"]["step"] = "09 mint"

        self.refused(change, "is not an earlier step")

    def test_an_input_that_spends_a_coin_already_spent(self):
        def change(chain):
            # Step 3 pays from the coin step 2 has already spent.
            taken = chain["steps"][1]["inputs"][1]
            chain["steps"][2]["inputs"][1] = copy.deepcopy(taken)

        self.refused(change, "was already spent by step 2 ('02 mint'), input 1")

    def test_a_spends_value_that_differs_from_the_output(self):
        def change(chain):
            chain["steps"][1]["inputs"][1]["spends"]["value"] += 1

        self.refused(change, "spends says the value is")

    def test_a_spends_covenant_id_that_differs_from_the_output(self):
        def change(chain):
            chain["steps"][1]["inputs"][0]["spends"]["covenant_id"] = None

        self.refused(change, "spends states another covenant id")

    def test_a_changed_sequence(self):
        def change(chain):
            chain["steps"][5]["inputs"][0]["sequence"] = 1

        self.refused(change, "step 6 ('06 minter split'): id mismatch")

    def test_a_changed_output_value(self):
        def change(chain):
            chain["steps"][0]["outputs"][2]["value"] += 1

        self.refused(change, "step 1 ('01 launch'): id mismatch")

    def test_the_wrong_network(self):
        def change(chain):
            chain["network"] = "mainnet"

        self.refused(change, "wrong network")

    def test_nothing_was_sent_must_be_true(self):
        def change(chain):
            chain["nothing_was_sent"] = False

        self.refused(change, "nothing_was_sent is not true")

    def test_a_covenant_output_bound_to_another_covenant_id(self):
        def change(chain):
            chain["steps"][2]["outputs"][0]["covenant_binding"]["covenant_id"] = "77" * 32

        self.refused(change, "bound to another covenant id")

    def test_a_covenant_id_that_the_first_step_does_not_give(self):
        def change(chain):
            # Changed everywhere alike, so the file agrees with itself; the SDK derives another id.
            chain["covenant_id"] = "77" * 32
            for transaction in chain["steps"] + chain["probes"]:
                for output in transaction["outputs"]:
                    if output["covenant_binding"]:
                        output["covenant_binding"]["covenant_id"] = "77" * 32
                for tx_input in transaction["inputs"]:
                    if tx_input["spends"]["covenant_id"]:
                        tx_input["spends"]["covenant_id"] = "77" * 32

        self.refused(change, "covenant id: for output 0 of the first step the SDK derives 01cec74a")

    def test_a_party_address_that_does_not_match_the_file(self):
        stranger = address(FOREIGN_KEY_SCRIPT[:2] + "22" * 32 + "ac")
        self.refused(lambda chain: None, "party 'alice': the address given does not match the file", {**PARTIES, "alice": stranger})

    def test_the_parties_named_must_be_the_parties_of_the_file(self):
        fewer = {name: at for name, at in PARTIES.items() if name != "payer"}
        self.refused(lambda chain: None, "they must be the same", fewer)

    def test_an_address_of_another_network_is_refused_before_anything_is_read(self):
        code, printed = self.check(parties={**PARTIES, "bob": "kaspa:qzk36qhmspxp3he5xjacufvkjsfq2ykxgymdsaeepk0tgec8lh0vyra3lp283"})
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("does not start with kaspatest:", printed)

    def test_funding_above_thirty_kas(self):
        def change(chain):
            chain["funding"]["value"] = 31 * KAS

        self.refused(change, "above the hard limit of 30.00000000 KAS")

    def test_a_funding_coin_that_is_not_its_owner_s(self):
        def change(chain):
            chain["funding"]["owner"] = "bob"

        self.refused(change, "the coin is not locked to the script of its owner 'bob'")

    def test_an_empty_signature_script(self):
        def change(chain):
            chain["steps"][6]["inputs"][1]["signature_script"] = ""

        self.refused(change, "step 7 ('07 mint from the split'), input 1: empty signature script")

    def test_fields_the_id_does_not_cover_are_bounded(self):
        def change(chain):
            chain["steps"][0]["mass"] = 0
            chain["steps"][1]["inputs"][0]["compute_budget"] = 5000

        printed = self.refused(change, "the mass field 0 is not between")
        self.assertIn("the compute budget 5000 is above", printed)
        self.assertNotIn("id mismatch", printed)  # the ids stay what they were: an id covers neither

    def test_a_coin_value_other_than_one_kas(self):
        def change(chain):
            chain["coin_value"] = 2 * KAS

        self.refused(change, "the run allows exactly 1.00000000")

    def test_a_covenant_coin_of_another_value(self):
        def change(chain):
            chain["steps"][1]["outputs"][1]["value"] = KAS + 1

        self.refused(change, "a covenant coin must hold 100000000")

    def test_an_output_of_an_unknown_role(self):
        def change(chain):
            chain["steps"][10]["outputs"][0]["role"] = "gift"

        self.refused(change, "the role 'gift' is not one of covenant, deposit, change")

    def test_a_covenant_output_without_a_binding(self):
        def change(chain):
            chain["steps"][1]["outputs"][0]["covenant_binding"] = None

        self.refused(change, "a covenant coin without a covenant binding")

    def test_a_step_the_builder_s_gate_did_not_pass(self):
        def change(chain):
            chain["steps"][3]["gate"]["mempool"] = False

        self.refused(change, "the builder's gate did not pass it (mempool)")

    def test_a_probe_the_builder_expects_to_be_accepted(self):
        def change(chain):
            chain["probes"][0]["expect"] = "accepted"
            chain["probes"][1]["gate"]["scripts"] = True
            chain["probes"][2]["gate"]["refusal"] = None

        printed = self.refused(change, 'a probe must say "refused"')
        self.assertIn("did not refuse it by its scripts", printed)
        self.assertIn("recorded no refusal", printed)

    def test_a_probe_that_spends_a_coin_the_steps_have_spent(self):
        def change(chain):
            spent = chain["steps"][1]["inputs"][0]  # the first minter coin, gone since step 2
            chain["probes"][0]["inputs"][0] = copy.deepcopy(spent)

        self.refused(change, "is not unspent after the last step")

    def test_a_probe_output_to_a_foreign_key(self):
        def change(chain):
            chain["probes"][1]["outputs"][1]["script_public_key"] = FOREIGN_KEY_SCRIPT

        printed = self.refused(change, "output 1: the change is said to go to 'payer', but its script is not that party's")
        self.assertIn("REFUSED  probe 2 (", printed)

    def test_too_many_steps_and_probes(self):
        def change(chain):
            chain["probes"] = [dict(probe, name=f"{probe['name']} #{copy_number}") for copy_number in range(4) for probe in chain["probes"]]
            chain["steps"] = []

        printed = self.refused(change, "12 probes; the run allows at most 10")
        self.assertIn("0 steps; the run allows 1 to 20", printed)

    def test_two_transactions_of_one_name(self):
        def change(chain):
            chain["steps"][5]["name"] = chain["steps"][4]["name"]

        self.refused(change, "the name '05 borrowed receive' is used by more than one transaction")

    def test_a_missing_field_is_named_and_the_other_checks_are_not_run(self):
        def change(chain):
            del chain["steps"][2]["inputs"][0]["sequence"]
            chain["steps"][4]["outputs"][0]["value"] = "100000000"

        printed = self.refused(change, "step 3 ('03 transfer'), input 0: the field 'sequence' is missing")
        self.assertIn("the field 'value' is not a whole number", printed)
        self.assertIn("the other checks were not run", printed)

    def test_a_file_that_is_not_json(self):
        path = self.folder / "chain.json"
        path.write_text("not json", encoding="utf-8")
        code, printed = run(["check", str(path), *party_args()])
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("does not read as JSON", printed)

    def test_usage_errors_end_with_the_check_code(self):
        for argv in ([], ["check"], ["check", "x.json"], ["frobnicate"], ["send", "x.json", "--party", "a=kaspatest:x"]):
            with self.subTest(argv=argv):
                code, _ = run(argv)
                self.assertEqual(code, ls.EXIT_CHECK)
        code, printed = run(["check", "x.json", "--party", "nonsense"])
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("--party wants NAME=ADDRESS", printed)

    def test_the_program_has_no_option_for_a_key(self):
        text = (HERE.parent / "launch_send.py").read_text(encoding="utf-8")
        for word in ("PrivateKey", "Keypair", "sign_transaction", "create_input_signature", "KEY_FILE"):
            self.assertNotIn(word, text)


@unittest.skipUnless(HAVE_HARNESS, NO_HARNESS)
class Locks(Folder):
    """Check h on real data: the fixture's states are the rehearsal's, its locks the builder's."""

    def test_every_lock_of_the_fixture_is_recomputed_from_its_state(self):
        code, printed = self.check(more=("--harness", HARNESS))
        self.assertEqual(code, 0, printed)
        self.assertIn("recomputed for 26 covenant outputs", printed)

    def test_a_state_that_does_not_give_the_lock_is_refused(self):
        chain = copy.deepcopy(FIXTURE)
        chain["steps"][1]["outputs"][1]["state"]["amount"] = 11  # the coin said to hold 10 tokens
        chain["steps"][0]["outputs"][0]["state"]["owner"] = FIXTURE["parties"]["bob"]["x_only_public_key"]
        code, printed = self.check(chain, more=("--harness", HARNESS))
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertEqual(printed.count("the lock recomputed from the state is"), 2)

    def test_the_builder_s_own_chain_passes_with_every_lock_recomputed(self):
        code, printed = self.check(SELFTEST, SELFTEST_PARTIES, more=("--harness", HARNESS))
        self.assertEqual(code, 0, printed)
        self.assertIn("recomputed for 27 covenant outputs", printed)
        self.assertIn("check: passed (offline). The network was not read.", printed)

    def test_a_token_coin_of_a_foreign_key_with_its_true_lock_is_refused(self):
        # The lock is the right one for the state, so the recomputation agrees; the owner is nobody's key.
        harness = ls.load_harness(HARNESS)
        chain = copy.deepcopy(FIXTURE)
        output = chain["steps"][1]["outputs"][1]
        output["state"]["owner"] = "11" * 32
        state = {name: bytes.fromhex(value) if name in ls.STATE_BYTES else value for name, value in output["state"].items() if name != "contract"}
        output["script_public_key"] = bytes(harness.lock("KCC20", state)).hex()
        code, printed = self.check(chain, more=("--harness", HARNESS))
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("the owner of the coin (" + "11" * 32 + ") is not the key of a party named on the command line", printed)
        self.assertNotIn("the lock recomputed from the state is", printed)

    def test_a_harness_that_cannot_be_loaded_is_a_refusal(self):
        code, printed = self.check(more=("--harness", str(self.folder / "nowhere")))
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("could not be loaded", printed)


# --------------------------------------------------------------------------
# check --online, status, prepare
# --------------------------------------------------------------------------


class Reading(Folder):
    def test_check_online_finds_the_funding_coin(self):
        node = FakeNode()
        code, printed = self.check(more=("--online",), node=node)
        self.assertEqual(code, 0, printed)
        self.assertIn("the funding coin is at its owner's address, unspent", printed)
        self.assertIn("the node's priority estimate now gives 309", printed)
        self.assertIn("NOTE - the node now asks for more than the file pays", printed)
        self.assertEqual(node.submitted, [])

    def test_check_online_refuses_when_the_funding_coin_is_not_there(self):
        code, printed = self.check(more=("--online",), node=FakeNode(funded=False))
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("neither the funding coin nor any coin of this chain is on chain", printed)

    def test_check_online_refuses_a_funding_coin_of_another_value(self):
        node = FakeNode(funded=False)
        funding = FIXTURE["funding"]
        node.put(funding["transaction_id"], funding["index"], funding["value"] - 1, funding["script_public_key"])
        code, printed = self.check(more=("--online",), node=node)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("the funding coin", printed)
        self.assertIn("amount 2999999999 instead of 3000000000", printed)

    def test_check_online_says_which_steps_are_on_chain(self):
        node = FakeNode()
        node.how[STEP_IDS[3]] = "refuse"
        self.send(node)
        code, printed = self.check(more=("--online",), node=node)
        self.assertEqual(code, 0, printed)
        self.assertIn("the first 3 of 13 steps are on chain ('01 launch', '02 mint', '03 transfer')", printed)

    def test_a_node_of_another_network_is_not_read(self):
        node = FakeNode(network="mainnet")
        code, printed = self.check(more=("--online",), node=node)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("Refusing: the node reports network 'mainnet'", printed)
        self.assertEqual(node.reads, 0)
        code, printed = self.check(more=("--online",), node=FakeNode(synced=False))
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("not synced", printed)

    def test_status_shows_how_far_the_chain_is(self):
        node = FakeNode()
        node.how[STEP_IDS[5]] = "refuse"
        self.send(node)
        code, printed = run(["status", self.chain_file(), *party_args()], node)
        self.assertEqual(code, 0, printed)
        self.assertIn("step  5 '05 borrowed receive': on chain; 3 of 3 outputs unspent", printed)
        self.assertIn("step  1 '01 launch': on chain; 0 of 3 outputs unspent", printed)
        self.assertIn("step  6 '06 minter split': no trace", printed)
        self.assertIn("the first 5 of 13 steps are on chain", printed)
        self.assertIn("balance: payer", printed)
        self.assertEqual(len(node.submitted), 6)  # `status` itself submitted nothing

    def test_after_a_dropped_connection_the_node_is_asked_again_what_it_is(self):
        node = FakeNode()
        node.failing_reads = [ConnectionError("WebSocket is not connected")]
        with mock.patch.object(ls.Timing, "read_pause_seconds", 0), contextlib.redirect_stdout(io.StringIO()):
            entries = asyncio.run(ls.utxos_at(node, PARTIES["issuer"]))
        self.assertEqual(len(entries), 1)
        self.assertEqual((node.reconnects, node.questions, node.reads), (1, 1, 2))
        # The node reached by the reconnect may be another one: it is not read.
        node = FakeNode(network="mainnet")
        node.failing_reads = [ConnectionError("WebSocket is not connected")]
        with mock.patch.object(ls.Timing, "read_pause_seconds", 0), self.assertRaises(ls.WrongNode):
            asyncio.run(ls.utxos_at(node, PARTIES["issuer"]))
        self.assertEqual(node.reads, 1)

    def test_a_node_that_never_answers_ends_the_command_in_one_line(self):
        node = FakeNode()
        node.failing_reads = [ConnectionError("WebSocket is not connected")] * 50
        code, printed = self.check(more=("--online",), node=node)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("The node could not be read", printed)


class Prepare(Folder):
    def prepare(self, node, *more) -> tuple:
        out = self.folder / "request.json"
        code, printed = run(["prepare", "--issuer-address", PARTIES["issuer"], "--out", str(out), *more], node)
        return code, printed, out

    def test_the_request_names_the_one_coin_of_thirty_kas(self):
        node = FakeNode()
        issuer = FIXTURE["parties"]["issuer"]["script_public_key"]
        node.put("ab" * 32, 1, 2 * KAS, issuer)
        node.put("ac" * 32, 0, 30 * KAS, issuer, covenant_id="cd" * 32)  # bound to a covenant: not a plain coin
        code, printed, out = self.prepare(node, "--token-name", "example")
        self.assertEqual(code, 0, printed)
        request = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(request["format"], "kcc20-launch-request/1")
        self.assertEqual(request["network"], "testnet-10")
        self.assertEqual(request["token_name"], "example")
        self.assertEqual((request["coin_value"], request["fee_cap_total"]), (KAS, 15 * KAS))
        self.assertEqual(request["feerate"], 309)  # the estimate 308.2, rounded up
        self.assertEqual(request["node"], node.url)
        funding = {name: FIXTURE["funding"][name] for name in request["funding"]}
        self.assertEqual(request["funding"], funding)
        self.assertNotIn(b"\r", out.read_bytes())
        self.assertIn("priority bucket", printed)
        self.assertEqual(node.submitted, [])

    def test_the_feerate_is_never_below_the_floor_and_can_be_given(self):
        node = FakeNode()
        node.rate = 1.5
        code, _, out = self.prepare(node)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["feerate"], 100)
        out.unlink()
        code, _, out = self.prepare(node, "--feerate", "955")
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["feerate"], 955)
        out.unlink()
        code, printed, out = self.prepare(node, "--feerate", "99")
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertFalse(out.exists())

    def test_no_coin_or_two_coins_of_the_funding_value_are_refused_with_a_list(self):
        issuer = FIXTURE["parties"]["issuer"]["script_public_key"]
        none = FakeNode(funded=False)
        none.put("ab" * 32, 1, 2 * KAS, issuer)
        two = FakeNode()
        two.put("ab" * 32, 1, 30 * KAS, issuer)
        for node, count in ((none, 0), (two, 2)):
            with self.subTest(coins=count):
                code, printed, out = self.prepare(node)
                self.assertEqual(code, ls.EXIT_CHECK)
                self.assertIn(f"Refusing: {count} plain coins of exactly 30.00000000 KAS", printed)
                self.assertIn("abababab", printed)
                self.assertFalse(out.exists())

    def test_an_existing_request_is_not_overwritten(self):
        node = FakeNode()
        out = self.folder / "request.json"
        out.write_text("kept", encoding="utf-8")
        code, printed, _ = self.prepare(node)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("Refusing to overwrite", printed)
        self.assertEqual(out.read_text(encoding="utf-8"), "kept")
        self.assertEqual(node.connections, 0)

    def test_limits_of_prepare(self):
        node = FakeNode()
        code, printed, _ = self.prepare(node, "--funding-kas", "31")
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("at most 30.00000000 KAS", printed)
        code, printed = run(["prepare", "--issuer-address", "kaspa:qqq", "--out", str(self.folder / "r.json")], node)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertEqual(node.connections, 0)


# --------------------------------------------------------------------------
# send
# --------------------------------------------------------------------------


class Send(Folder):
    def test_the_whole_run(self):
        node = FakeNode()
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS)
        self.assertIn("finished: 13 steps on chain; 3 probes refused, 0 of them for another reason", printed)
        # The node was asked what it is on connecting and right before each of the 16 submissions.
        self.assertEqual(node.questions, 1 + 16)
        # What was handed over carries what an id does not cover, as the file has it.
        for shown, transaction in zip(node.handed, FIXTURE["steps"] + FIXTURE["probes"]):
            self.assertEqual(shown["mass"], transaction["mass"])
            for have, want in zip(shown["inputs"], transaction["inputs"]):
                self.assertEqual(have["signatureScript"], want["signature_script"])
                self.assertEqual(have["computeBudget"], want["compute_budget"])
        events = self.events()
        told = [event["what"] for event in events]
        self.assertEqual(told[:2], ["run started", "balances before"])
        self.assertEqual(len(events[0]["chain_sha256"]), 64)
        self.assertEqual(told[-2:], ["balances after", "run finished"])
        self.assertEqual(told.count("step accepted"), 13)
        self.assertEqual(told.count("step seen"), 13)
        self.assertEqual(told.count("probe refused"), 3)
        for event in events:
            self.assertEqual((event["node"], event["node_version"]), (node.url, "0.0.0-fake"))
            self.assertRegex(event["time_utc"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        seen = [event for event in events if event["what"] == "step seen"][0]
        self.assertEqual(seen["transaction_id"], STEP_IDS[0])
        self.assertEqual(len(seen["entries_seen"]), 3)
        self.assertEqual(seen["entries_seen"][0]["covenant_id"], FIXTURE["covenant_id"])
        refused = [event for event in events if event["what"] == "probe refused"][0]
        self.assertEqual(refused["answer"], f"Rejected transaction {PROBE_IDS[0]}: {SCRIPT_REFUSAL}")
        # Balances before the first submission and after the last.
        before = events[1]["balances"]
        after = events[-2]["balances"]
        self.assertEqual(before["issuer"]["sompi"], 30 * KAS)
        self.assertEqual(before["payer"]["sompi"], 0)
        self.assertEqual(after["issuer"]["sompi"], KAS)  # the deposit of the closed minter
        self.assertEqual(after["bob"]["sompi"], 2 * KAS)
        self.assertEqual(after["payer"]["sompi"], FIXTURE["totals"]["change_at_the_end"])
        # No signature script goes into the record whole: its first 16 characters and its length do.
        text = self.record_text()
        self.assertNotIn("5a" * 9, text)
        self.assertIn('"signature_script_starts": "5a5a5a5a5a5a5a5a"', text)
        self.assertIn('"signature_script_bytes": 66', text)

    def test_without_the_flag_nothing_is_sent(self):
        node = FakeNode()
        code, printed = self.send(node, flag=False)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("--yes-send-to-testnet-10", printed)
        self.assertEqual((node.submitted, node.connections), ([], 0))
        self.assertFalse((self.folder / "record").exists())

    def test_a_file_that_fails_a_check_is_not_sent(self):
        chain = copy.deepcopy(FIXTURE)
        chain["steps"][12]["outputs"][2]["script_public_key"] = FOREIGN_KEY_SCRIPT
        node = FakeNode()
        code, printed = self.send(node, chain)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertEqual((node.submitted, node.connections), ([], 0))

    def test_a_refused_step_stops_the_run(self):
        node = FakeNode()
        node.how[STEP_IDS[3]] = "refuse"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_REFUSED, printed)
        self.assertEqual(node.submitted, STEP_IDS[:4])  # nothing after it, no second try
        self.assertIn("REFUSED by the node", printed)
        refused = [event for event in self.events() if event["what"] == "step refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["answer"], f"Rejected transaction {STEP_IDS[3]}: {SCRIPT_REFUSAL}")
        last = self.events()[-1]
        self.assertEqual((last["what"], last["exit_code"]), ("run stopped", ls.EXIT_REFUSED))
        # Where the money stands at the stop: three steps were paid for, the change is the payer's.
        self.assertEqual(last["balances"]["payer"]["sompi"], FIXTURE["steps"][2]["outputs"][2]["value"])
        self.assertEqual(last["balances"]["issuer"]["sompi"], 0)

    def test_a_lost_answer_counts_as_accepted_once_the_outputs_are_seen(self):
        node = FakeNode()
        node.how[STEP_IDS[2]] = "lost-applied"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS)
        self.assertIn("NO ANSWER (WebSocket is not connected); looking for its outputs", printed)
        accepted = [event for event in self.events() if event["what"] == "step accepted" and event["transaction_id"] == STEP_IDS[2]]
        self.assertEqual(accepted[0]["how"], "outputs seen after a lost answer")

    def test_a_lost_answer_without_outputs_stops_the_run(self):
        node = FakeNode()
        node.how[STEP_IDS[2]] = "lost"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NO_ANSWER, printed)
        self.assertEqual(node.submitted, STEP_IDS[:3])
        self.assertIn("NO ANSWER from the node", printed)
        self.assertIn("Run `status` later", printed)
        self.assertEqual([e["what"] for e in self.events()][-2:], ["step no answer", "run stopped"])

    def test_outputs_that_never_appear_stop_the_run(self):
        node = FakeNode()
        node.how[STEP_IDS[1]] = "accept-hidden"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NOT_SEEN, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])  # not submitted again
        self.assertIn("submitted, not seen", printed)
        self.assertEqual([e["what"] for e in self.events()][-3:], ["step accepted", "step not seen", "run stopped"])

    def test_an_accepted_probe_stops_the_run_at_once(self):
        node = FakeNode()
        node.how[PROBE_IDS[1]] = "accept"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_FORBIDDEN_ACCEPTED, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:2])  # the third probe was not sent
        self.assertIn("FORBIDDEN MOVE ACCEPTED", printed)
        self.assertEqual([e["what"] for e in self.events()][-2:], ["probe accepted", "run stopped"])

    def test_a_probe_taken_without_an_answer_is_a_forbidden_move_accepted(self):
        node = FakeNode()
        node.how[PROBE_IDS[0]] = "lost-applied"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_FORBIDDEN_ACCEPTED, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])
        self.assertIn("FORBIDDEN MOVE ACCEPTED", printed)

    def test_a_probe_without_an_answer_and_without_outputs_stops_the_run(self):
        node = FakeNode()
        node.how[PROBE_IDS[0]] = "lost"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NO_ANSWER, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])
        self.assertEqual([e["what"] for e in self.events()][-2:], ["probe no answer", "run stopped"])

    def test_a_probe_refused_for_another_reason_is_told_apart_and_the_run_goes_on(self):
        node = FakeNode()
        node.how[PROBE_IDS[0]] = "refuse-fee"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS)
        self.assertIn("REFUSED FOR ANOTHER REASON", printed)
        self.assertIn("3 probes refused, 1 of them for another reason", printed)
        other = [event for event in self.events() if event["what"] == "probe refused for another reason"]
        self.assertEqual(other[0]["answer"], f"Rejected transaction {PROBE_IDS[0]}: {FEE_REFUSAL}")

    def test_a_node_of_another_network_is_handed_nothing(self):
        for wrong in (dict(network="mainnet"), dict(network="testnet-11"), dict(synced=False)):
            with self.subTest(**wrong):
                node = FakeNode(**wrong)
                code, printed = self.send(node)
                self.assertEqual(code, ls.EXIT_CHECK, printed)
                self.assertIn("Refusing: the node", printed)
                self.assertEqual((node.submitted, node.reads), ([], 0))

    def test_a_node_that_turns_into_another_network_is_handed_nothing_more(self):
        node = FakeNode()
        node.wrong_after = 3  # the connection and two submissions; the third question gets another answer
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NODE, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])
        self.assertIn("Not sent: Refusing: the node reports network 'mainnet'", printed)

    def test_a_submission_that_never_returns_is_a_lost_answer(self):
        node = FakeNode()
        submit = node.submit_transaction

        async def hang_on_the_second(request):
            if len(node.submitted) == 1:
                node.submitted.append(request["transaction"].to_dict()["id"])
                await asyncio.sleep(3600)
            return await submit(request)

        node.submit_transaction = hang_on_the_second
        with mock.patch.object(ls.Timing, "answer_timeout", 0.05):
            code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NO_ANSWER, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])
        self.assertIn("NO ANSWER (TimeoutError)", printed)

    def test_another_id_from_the_node_stops_the_run(self):
        node = FakeNode()
        node.how[STEP_IDS[0]] = "other-id"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, STEP_IDS[:1])
        self.assertIn("the node accepted it under the id eeee", printed)

    def test_a_run_goes_on_after_a_stop_and_sends_no_accepted_step_twice(self):
        node = FakeNode()
        node.how[STEP_IDS[4]] = "refuse"
        code, _ = self.send(node)
        self.assertEqual((code, node.submitted), (ls.EXIT_REFUSED, STEP_IDS[:5]))
        del node.how[STEP_IDS[4]]
        # The next run with the same record does not hand the refused step over again by itself.
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_CHECK, printed)
        self.assertIn("an earlier run with this record folder stopped at '05 borrowed receive' (step refused)", printed)
        self.assertIn("--again-after-a-stop", printed)
        self.assertEqual(node.submitted, STEP_IDS[:5])
        # With the operator's word it does, and says so on screen and in the record.
        code, printed = self.send(node, more=("--again-after-a-stop",))
        self.assertEqual(code, ls.EXIT_OK, printed)
        # It starts at the step that was refused: the four before it are not handed over again.
        self.assertEqual(node.submitted, STEP_IDS[:5] + STEP_IDS[4:] + PROBE_IDS)
        self.assertIn("step  1 '01 launch': already done, not sent", printed)
        self.assertIn("step  4 '04 seed create': already done, not sent", printed)
        self.assertIn("the first 4 of 13 steps are on chain", printed)
        self.assertIn("HANDED OVER AGAIN by the operator's decision (--again-after-a-stop); an earlier run recorded 'step refused'", printed)
        self.assertIn("steps   : 9 handed over and seen on chain, 4 found on chain already; 13 in all", printed)
        again = [e for e in self.events() if e.get("again_by_the_operator_after")]
        self.assertEqual([(e["what"], e["transaction_id"]) for e in again], [("step submitting", STEP_IDS[4])])
        self.assertEqual(len(list((self.folder / "record").glob("run-*.jsonl"))), 2)

    def test_a_step_handed_over_again_and_accepted_is_only_waited_for_after_that(self):
        node = FakeNode()
        node.how[STEP_IDS[4]] = "refuse"
        self.assertEqual(self.send(node)[0], ls.EXIT_REFUSED)
        node.how[STEP_IDS[4]] = "accept-hidden"
        self.assertEqual(self.send(node, more=("--again-after-a-stop",))[0], ls.EXIT_NOT_SEEN)
        # Accepted now: the old refusal no longer stands in the way, and the step is not handed over a third time.
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NOT_SEEN, printed)
        self.assertIn("an earlier run recorded it as accepted; not sent again", printed)
        self.assertEqual(collections.Counter(node.submitted)[STEP_IDS[4]], 2)

    def test_a_step_with_a_lost_answer_is_not_handed_over_again_by_itself(self):
        node = FakeNode()
        node.how[STEP_IDS[4]] = "lost"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NO_ANSWER)
        self.assertIn("it hands the step over again only with --again-after-a-stop", printed)
        del node.how[STEP_IDS[4]]
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_CHECK, printed)
        self.assertIn("(step no answer)", printed)
        self.assertEqual(node.submitted, STEP_IDS[:5])
        # Had the node taken it after all, the step is on chain and the run goes on by itself.
        node.apply(node.handed[4])
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(collections.Counter(node.submitted)[STEP_IDS[4]], 1)

    def test_a_run_goes_on_without_the_earlier_record(self):
        node = FakeNode()
        node.how[STEP_IDS[8]] = "lost"
        code, _ = self.send(node)
        self.assertEqual(code, ls.EXIT_NO_ANSWER)
        del node.how[STEP_IDS[8]]
        # Another record folder: what is done is told from the chain alone. Step 1 has no unspent
        # output left by now; a later step that is on chain spends them.
        code, printed = self.send(node, record="another")
        self.assertEqual(code, ls.EXIT_OK, printed)
        counts = collections.Counter(node.submitted)
        self.assertEqual([counts[txid] for txid in STEP_IDS], [1] * 8 + [2] + [1] * 4)
        self.assertIn("a later step that spends its outputs is on chain", printed)

    def test_a_step_accepted_but_not_seen_is_waited_for_and_never_sent_again(self):
        node = FakeNode()
        node.how[STEP_IDS[1]] = "accept-hidden"
        code, _ = self.send(node)
        self.assertEqual(code, ls.EXIT_NOT_SEEN)
        # Still not there: the next run waits and stops again, without handing it over a second time.
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NOT_SEEN, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])
        self.assertIn("an earlier run recorded it as accepted; not sent again", printed)
        # Once it is on chain the run goes on from the next step.
        node.apply(node.handed[1])
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS)

    def test_a_chain_whose_funding_coin_is_gone_is_not_started(self):
        node = FakeNode(funded=False)
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, [])
        self.assertIn("neither the funding coin nor any coin of this chain is on chain", printed)

    def test_a_step_whose_inputs_are_gone_is_not_submitted(self):
        node = FakeNode()
        # While step 3 is sent, the seed coin that step 4 needs disappears (it was made by step 1
        # and seen then): the picture no longer fits the file.
        original = node.submit_transaction

        async def submit_and_steal(request):
            answer = await original(request)
            if len(node.submitted) == 3:
                seed_coin = FIXTURE["steps"][3]["inputs"][0]
                for coins in node.coins.values():
                    coins.pop((seed_coin["transaction_id"], seed_coin["index"]), None)
            return answer

        node.submit_transaction = submit_and_steal
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, STEP_IDS[:3])
        self.assertIn("not all of its inputs are on chain, and nothing on chain shows that it was sent", printed)
        self.assertIn("(seed of issuer)", printed)
        self.assertIn("Nothing was submitted", printed)
        self.assertEqual([e["what"] for e in self.events()][-2:], ["stopped", "run stopped"])

    def test_a_probe_whose_inputs_are_gone_is_not_submitted(self):
        node = FakeNode()
        original = node.submit_transaction

        async def submit_and_steal(request):
            answer = await original(request)
            if len(node.submitted) == len(STEP_IDS):
                coin = FIXTURE["probes"][0]["inputs"][0]
                for coins in node.coins.values():
                    coins.pop((coin["transaction_id"], coin["index"]), None)
            return answer

        node.submit_transaction = submit_and_steal
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, STEP_IDS)
        self.assertIn("A refusal would prove nothing", printed)

    def test_reads_that_fail_for_good_before_a_submission_stop_the_run(self):
        node = FakeNode()
        submit, read = node.submit_transaction, node.get_utxos_by_addresses
        since = {"reads": 0}

        async def counting_submit(request):
            since["reads"] = 0
            return await submit(request)

        async def read_until_silent(request):
            # Step 3 is seen with three reads (its outputs sit at three addresses); then the node goes silent.
            since["reads"] += 1
            if len(node.submitted) == 3 and since["reads"] > 3:
                raise ConnectionError("WebSocket is not connected")
            return await read(request)

        node.submit_transaction, node.get_utxos_by_addresses = counting_submit, read_until_silent
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_NODE, printed)
        self.assertEqual(node.submitted, STEP_IDS[:3])
        self.assertIn("step  3 '03 transfer': all 3 outputs seen", printed)
        self.assertIn("STOP: the node could not be read", printed)
        self.assertEqual(self.events()[-1]["exit_code"], ls.EXIT_NODE)

    def test_reads_that_fail_for_good_after_a_submission_leave_it_submitted_not_seen(self):
        node = FakeNode()
        original = node.submit_transaction

        async def submit_then_go_silent(request):
            answer = await original(request)
            if len(node.submitted) == 3:
                node.failing_reads = [ConnectionError("WebSocket is not connected")] * 50
            return answer

        node.submit_transaction = submit_then_go_silent
        code, printed = self.send(node)
        # The third step was accepted, and its outputs could not be looked for: submitted, not seen.
        self.assertEqual(code, ls.EXIT_NOT_SEEN, printed)
        self.assertEqual(node.submitted, STEP_IDS[:3])
        self.assertIn("the look-up stopped", printed)


class AfterTheReview(Folder):
    """Points of a review of the program before the run: each test states what the program does now."""

    # --- 1. covenant outputs are coins of the token's contracts, owned by a party

    def test_send_does_not_start_without_a_harness(self):
        node = FakeNode()
        code, printed = self.send(node, harness=False)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("`send` needs --harness", printed)
        self.assertEqual((node.submitted, node.connections), ([], 0))

    def test_a_covenant_output_without_a_state_is_refused_in_steps_and_probes(self):
        for group, harness in (("steps", ()), ("probes", ()), ("steps", ("--harness", str(STAND_IN_FOLDER)))):
            with self.subTest(group=group, harness=bool(harness)):
                chain = copy.deepcopy(FIXTURE)
                chain[group][0]["outputs"][0]["state"] = None
                code, printed = self.check(chain, more=harness)
                self.assertEqual(code, ls.EXIT_CHECK)
                self.assertIn("output 0: a covenant coin without a state", printed)

    def test_a_foreign_pay_to_script_hash_output_is_not_sent(self):
        # An output in the form of a covenant coin, locked to a script of somebody else, with no state or a lying one.
        for state in (None, FIXTURE["steps"][1]["outputs"][1]["state"]):
            with self.subTest(state=bool(state)):
                chain = copy.deepcopy(FIXTURE)
                chain["probes"][0]["outputs"][0]["script_public_key"] = "aa20" + "33" * 32 + "87"
                chain["probes"][0]["outputs"][0]["state"] = state
                node = FakeNode(chain)
                code, printed = self.send(node, chain)
                self.assertEqual(code, ls.EXIT_CHECK, printed)
                self.assertEqual((node.submitted, node.connections), ([], 0))

    def test_the_owner_of_every_coin_is_a_party_and_a_token_coin_is_owned_by_a_plain_key(self):
        chain = copy.deepcopy(FIXTURE)
        chain["steps"][0]["outputs"][0]["state"]["owner"] = "11" * 32  # a minter
        chain["steps"][0]["outputs"][1]["state"]["owner"] = "22" * 32  # a seed
        chain["steps"][1]["outputs"][1]["state"]["owner"] = "33" * 32  # a token coin
        chain["steps"][2]["outputs"][0]["state"]["owner_scheme"] = 3
        code, printed = self.check(chain)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertEqual(printed.count("is not the key of a party named on the command line"), 3)
        self.assertIn("the owner scheme is 3; this run allows only 0 (pay to a public key, Schnorr)", printed)

    # --- 2. a probe that may be with a node

    def test_a_probe_the_node_already_has_is_a_loud_stop(self):
        node = FakeNode()
        node.how[PROBE_IDS[0]] = "refuse-already"
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_FORBIDDEN_ACCEPTED, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])  # the other probes were not sent
        self.assertIn("FORBIDDEN MOVE MAY BE WITH A NODE", printed)
        self.assertIn("the probe is in a node's mempool or on chain", printed)
        self.assertNotIn("REFUSED FOR ANOTHER REASON", printed)
        self.assertEqual([e["what"] for e in self.events()][-2:], ["probe already with a node", "run stopped"])

    def test_no_run_starts_while_a_probe_of_an_earlier_run_may_be_with_a_node(self):
        cases = (("accept", ls.EXIT_FORBIDDEN_ACCEPTED, "probe accepted"), ("lost", ls.EXIT_NO_ANSWER, "probe no answer"),
                 ("refuse-already", ls.EXIT_FORBIDDEN_ACCEPTED, "probe already with a node"))
        for number, (how, code, what) in enumerate(cases):
            with self.subTest(how=how):
                record = f"record-{number}"
                node = FakeNode()
                node.how[PROBE_IDS[0]] = how
                first, _ = self.send(node, record=record)
                self.assertEqual(first, code)
                sent, connections = list(node.submitted), node.connections
                for more in ((), ("--again-after-a-stop",)):  # no flag overrides it
                    again, printed = self.send(node, record=record, more=more)
                    self.assertEqual(again, code, printed)
                    self.assertIn(f"the record folder holds {what!r} for ['P1 more out than in']", printed)
                    self.assertIn("a forbidden move may be on its way or on chain", printed)
                self.assertEqual((node.submitted, node.connections), (sent, connections))

    # --- 3. what an earlier record says is not proof that a step is on chain

    def test_a_step_recorded_as_accepted_whose_inputs_are_gone_stops_the_run(self):
        node = FakeNode()
        node.how[STEP_IDS[1]] = "accept-hidden"
        code, _ = self.send(node)
        self.assertEqual(code, ls.EXIT_NOT_SEEN)
        # The coins step 2 spends disappear, and none of its outputs is there: only the record speaks for it.
        for tx_input in FIXTURE["steps"][1]["inputs"]:
            for coins in node.coins.values():
                coins.pop((tx_input["transaction_id"], tx_input["index"]), None)
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])
        self.assertNotIn("already done", printed.split("step  2")[-1])
        self.assertNotIn("in all", printed)  # nothing is said about all steps being on chain

    # --- 4. no path of this machine in the record

    def test_the_record_names_files_by_name_and_hash_only(self):
        node = FakeNode()
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        started = self.events()[0]
        self.assertEqual(started["chain_file"], "chain.json")
        self.assertEqual(len(started["harness_sha256"]), 64)
        text = self.record_text()
        for part in (str(self.folder), self.folder.name, str(STAND_IN_FOLDER), STAND_IN_FOLDER.name, str(Path.home())):
            self.assertNotIn(part, text)
            self.assertNotIn(part.replace("\\", "\\\\"), text)
        self.assertNotIn(str(self.folder), printed)
        self.assertRegex(printed, r"record  : run-\d{8}T\d{12}Z\.jsonl")

    # --- 5. the fields an id covers hold nothing but the plain values

    def test_a_payload_and_the_like_are_refused(self):
        changes = (("payload", "6869"), ("gas", 1), ("lock_time", 5), ("subnetwork_id", "01" + "00" * 19), ("version", 0))
        for field, value in changes:
            with self.subTest(field=field):
                chain = copy.deepcopy(FIXTURE)
                chain["steps"][3][field] = value
                code, printed = self.check(chain)
                self.assertEqual(code, ls.EXIT_CHECK)
                self.assertIn(f"step 4 ('04 seed create'): {field} is {value!r}; a transaction of this run has only", printed)
        chain = copy.deepcopy(FIXTURE)
        chain["probes"][0]["inputs"][0]["sequence"] = 7
        chain["probes"][1]["inputs"][1]["sig_op_count"] = 1
        code, printed = self.check(chain)
        self.assertIn("input 0: sequence is 7; a transaction of this run has only 0 there", printed)
        self.assertIn("input 1: sig_op_count is 1; a transaction of this run has only 0 there", printed)

    # --- 6. robustness

    def test_an_interrupt_at_a_probe_hand_over_ends_the_run_and_blocks_the_next(self):
        node = FakeNode()
        submit = node.submit_transaction

        async def cancelled_at_the_first_probe(request):
            if len(node.submitted) == len(STEP_IDS):
                node.submitted.append(request["transaction"].to_dict()["id"])
                raise asyncio.CancelledError()
            return await submit(request)

        node.submit_transaction = cancelled_at_the_first_probe
        code, printed = self.send(node)
        self.assertEqual(code, 130, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])  # recorded, never gone on from
        last = self.events()[-1]
        self.assertEqual((last["what"], last["transaction_id"]), ("probe interrupted", PROBE_IDS[0]))
        self.assertIn(f"transaction {PROBE_IDS[0]}, was being handed over: it may or may not have reached the node", printed)
        # The probe may be with a node: no later run with this record starts, with or without the flag.
        node.submit_transaction = submit
        for more in ((), ("--again-after-a-stop",)):
            code, printed = self.send(node, more=more)
            self.assertEqual(code, ls.EXIT_NO_ANSWER, printed)
            self.assertIn("'probe handed over, outcome unknown' for ['P1 more out than in']", printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])

    def test_an_interrupt_of_the_run_during_a_step_hand_over_is_not_swallowed(self):
        # What the first Ctrl-C is to the program: a cancel of its main task, here while the node's answer is awaited.
        node = FakeNode()
        submit = node.submit_transaction

        async def slow_answer_and_a_cancel(request):
            if len(node.submitted) == 2:
                answer = await submit(request)  # the node takes the third step
                asyncio.get_running_loop().call_later(0.01, asyncio.current_task().cancel)
                await asyncio.sleep(5)
                return answer
            return await submit(request)

        node.submit_transaction = slow_answer_and_a_cancel
        code, printed = self.send(node)
        self.assertEqual(code, 130, printed)
        self.assertEqual(node.submitted, STEP_IDS[:3])  # nothing was handed over after the interrupt
        last = self.events()[-1]
        self.assertEqual((last["what"], last["step"], last["transaction_id"]), ("step interrupted", "03 transfer", STEP_IDS[2]))
        self.assertIn(f"transaction {STEP_IDS[2]}, was being handed over", printed)
        self.assertIn("Run `status`", printed)
        # The node had taken it: the step is on chain, so the next run goes on by itself and does not hand it over twice.
        node.submit_transaction = submit
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS)

    def killed_at(self, target: str) -> FakeNode:
        """A node at whose hand-over of `target` the program dies: the node does not take it, nothing more is recorded."""
        node = FakeNode()
        submit = node.submit_transaction

        async def die(request):
            if request["transaction"].to_dict()["id"] == target and not node.dead:
                node.dead = True
                node.submitted.append(target)
                raise SystemExit(9)
            return await submit(request)

        node.dead = False
        node.submit_transaction = die
        return node

    def test_a_step_whose_outcome_never_reached_the_record_is_not_handed_over_again_by_itself(self):
        node = self.killed_at(STEP_IDS[4])
        with self.assertRaises(SystemExit):
            self.send(node)
        self.assertEqual([e["what"] for e in self.events() if e.get("step") == "05 borrowed receive"], ["step submitting"])
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_CHECK, printed)
        self.assertIn("stopped at '05 borrowed receive' (step handed over, outcome unknown)", printed)
        self.assertIn("the earlier hand-over may or may not have reached the node", printed)
        self.assertEqual(node.submitted.count(STEP_IDS[4]), 1)
        # By the operator's decision it is handed over again, and the screen says after what.
        code, printed = self.send(node, more=("--again-after-a-stop",))
        self.assertEqual(code, ls.EXIT_OK, printed)
        self.assertIn("an earlier run recorded 'step handed over, outcome unknown'", printed)
        self.assertEqual(node.submitted.count(STEP_IDS[4]), 2)

    def test_a_probe_whose_outcome_never_reached_the_record_blocks_every_later_run(self):
        node = self.killed_at(PROBE_IDS[0])
        with self.assertRaises(SystemExit):
            self.send(node)
        self.assertEqual(self.events()[-1]["what"], "probe submitting")
        for more in ((), ("--again-after-a-stop",)):
            code, printed = self.send(node, more=more)
            self.assertEqual(code, ls.EXIT_NO_ANSWER, printed)
            self.assertIn("a forbidden move may be on its way or on chain", printed)
        self.assertEqual(node.submitted, STEP_IDS + PROBE_IDS[:1])

    def test_a_record_that_cannot_be_written_stops_the_run_with_its_own_code(self):
        node = FakeNode()
        submit = node.submit_transaction
        sync = os.fsync

        def failing_sync(descriptor):
            if len(node.submitted) >= 2:
                raise OSError(28, "No space left on device")
            return sync(descriptor)

        with mock.patch.object(ls.os, "fsync", failing_sync):
            code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_RECORD, printed)
        self.assertEqual(node.submitted, STEP_IDS[:2])  # nothing is submitted that cannot be recorded first
        self.assertIn("RECORD NOT WRITTEN (OSError: No space left on device)", printed)
        self.assertIn("the record could not be written. Nothing more was submitted.", printed)
        # What could not be written is on screen instead, the acceptance of the second step among it.
        self.assertIn('"what": "step accepted", "step": "02 mint"', printed)

    def test_a_record_write_that_raises_at_any_moment_never_hides_the_stop(self):
        real = ls.Record.write
        codes = set()
        for fail_at in (1, 2, 3, 4, 5, 6, 9, 20, 43, 46, 47, 48, 49):
            with self.subTest(fail_at=fail_at):
                count = {"writes": 0}

                def write(record, what, _count=count, _fail=fail_at, **fields):
                    _count["writes"] += 1
                    if _count["writes"] >= _fail:
                        raise OSError(28, "No space left on device")
                    return real(record, what, **fields)

                node = FakeNode()
                with mock.patch.object(ls.Record, "write", write):
                    code, printed = self.send(node, record=f"record-{fail_at}")  # no exception leaves the program
                codes.add(code)
                self.assertIn(code, (ls.EXIT_CHECK, ls.EXIT_RECORD), printed)
                self.assertIn("RECORD NOT WRITTEN (OSError: No space left on device)", printed)
                # Nothing is handed over once a line could not be written; what was handed over is in order.
                self.assertEqual(node.submitted, (STEP_IDS + PROBE_IDS)[: len(node.submitted)])
                self.assertLessEqual(len(node.submitted), fail_at // 3 + 1)
        self.assertEqual(codes, {ls.EXIT_CHECK, ls.EXIT_RECORD})

    def test_a_record_file_that_is_not_text_does_not_end_the_program(self):
        (self.folder / "record").mkdir()
        (self.folder / "record" / "run-old.jsonl").write_bytes(b"\xff\xfe\x00{\n" + b'{"what": "step accepted"}\n')
        node = FakeNode()
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_OK, printed)

    def test_a_key_given_twice_in_the_file_is_refused(self):
        path = self.folder / "chain.json"
        text = json.dumps(FIXTURE)
        path.write_text(text.replace('"nothing_was_sent": true', '"nothing_was_sent": false, "nothing_was_sent": true', 1), encoding="utf-8")
        code, printed = run(["check", str(path), *party_args()])
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("the key 'nothing_was_sent' is there twice in one object", printed)

    def test_a_coin_the_node_lists_twice_stops_before_anything_is_sent(self):
        node = FakeNode()
        read = node.get_utxos_by_addresses

        async def listing_twice(request):
            answer = await read(request)
            return {"entries": answer["entries"] * 2}

        node.get_utxos_by_addresses = listing_twice
        code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, [])
        self.assertIn("more than one entry for this outpoint in the node's answer", printed)

    # --- 7. the first step is built for sending before anything is sent

    def test_check_online_builds_the_first_step_from_the_node_s_own_entry(self):
        code, printed = self.check(more=("--online",), node=FakeNode())
        self.assertEqual(code, 0, printed)
        self.assertIn("the first step ('01 launch') builds for sending from the node's own entry of the funding coin; not submitted", printed)

    def test_an_entry_the_sdk_does_not_take_is_found_out_before_anything_is_sent(self):
        node = FakeNode()
        failing = mock.Mock(side_effect=ValueError("missing field `blockDaaScore`"))
        with mock.patch.object(ls, "UtxoEntryReference", mock.Mock(from_dict=failing)):
            code, printed = self.check(more=("--online",), node=node)
            self.assertEqual(code, ls.EXIT_CHECK, printed)
            self.assertIn("could not be built for sending from the node's own entry of the funding coin (ValueError: missing field", printed)
            code, printed = self.send(node)
        self.assertEqual(code, ls.EXIT_INCONSISTENT, printed)
        self.assertEqual(node.submitted, [])

    # --- 8. the funding coin is the issuer's

    def test_with_a_party_named_issuer_the_funding_coin_is_the_issuer_s(self):
        chain = copy.deepcopy(FIXTURE)
        chain["funding"]["owner"] = "payer"
        code, printed = self.check(chain)
        self.assertEqual(code, ls.EXIT_CHECK)
        self.assertIn("with a party named 'issuer' the funding coin must be the issuer's", printed)


class TheBuilderSChain(Folder):
    """The chain file of the builder's self-test, with three parties (covenant signature scripts replaced by placeholders)."""

    def test_it_passes_the_offline_checks(self):
        code, printed = self.check(SELFTEST, SELFTEST_PARTIES, more=("--harness", str(STAND_IN_FOLDER)))
        self.assertEqual(code, 0, printed)
        self.assertNotIn("REFUSED", printed)
        self.assertIn("recomputed for 27 covenant outputs", printed)
        self.assertIn("derived by the SDK from the first step, 2 output(s)", printed)
        self.assertNotIn("note: totals.", printed)

    def test_it_runs_through_against_the_fake_node(self):
        node = FakeNode(SELFTEST)
        code, printed = self.send(node, SELFTEST, parties=SELFTEST_PARTIES)
        self.assertEqual(code, ls.EXIT_OK, printed)
        ids = [t["transaction_id"] for t in SELFTEST["steps"] + SELFTEST["probes"]]
        self.assertEqual(node.submitted, ids)
        after = [e for e in self.events() if e["what"] == "balances after"][0]["balances"]
        self.assertEqual(after["issuer"]["sompi"], SELFTEST["totals"]["change_at_the_end"] + ls.COIN_VALUE)


if __name__ == "__main__":
    unittest.main()
