#!/usr/bin/env node
// Mutation runs of the checks of crates/checks.
//
//   node tools/mutation-run.mjs rules      [options]
//   node tools/mutation-run.mjs artifacts  <list.json> [options]
//
// rules      For every rule of data/rule-inventory.json whose refusing opcode is OpVerify,
//            OpEqualVerify or OpNumEqualVerify: neutralise that opcode (CHECKS_MUTANT) and
//            run again the cases of the baseline in which an input was refused exactly
//            there. Each case is then: now accepted (the rule was its only guard), refused
//            by another rule, refused by the engine, refused at another input of the same
//            transaction, or, flagged in the summary, unchanged or not run.
// artifacts  For every entry {id, artifact, contracts} of the list: run all cases of the
//            baseline against the contracts of that artifact (CHECKS_ARTIFACT) and report
//            the cases whose script verdict flipped.
//
// The baseline is the set of result files of an ordinary run, target/check-results/*.jsonl.
// It is only read. Every mutant writes into a folder of its own under target/mutation/.
//
// Options
//   --tests a,b,c     only these test binaries (default: every file of the baseline)
//   --rules K-37,M-19 rules campaign: only these rules
//   --baseline DIR    the baseline (default <target>/check-results)
//   --out DIR         where to write (default <target>/mutation)
//   --jobs N          test executables running at a time, 1 to 3 (default 3)
//   --threads N       test threads per executable, at least 2 (default 2)
//   --timeout SEC     per executable (default 900)
//   --alone-limit N   cases per mutant that may be repeated one by one (default 40)
//   --no-build        do not call cargo; take the newest executables of target/debug/deps
//   --dry-run         say what would run and stop
//
// No dependencies. Run it from a shell in which `cargo test --frozen -p checks` works.

import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NEUTRALISED = { OpVerify: 'OpDrop', OpEqualVerify: 'Op2Drop', OpNumEqualVerify: 'Op2Drop' };
const MODE_VARIABLES = [
  'CHECKS_MUTANT',
  'CHECKS_ARTIFACT',
  'CHECKS_OBSERVE',
  'CHECKS_ONLY_CASES',
  'CHECKS_FAST',
  'CHECKS_UNSELECTED',
  'CHECK_RESULTS_DIR',
];

// ---------------------------------------------------------------------------------------
// Arguments

function parseArguments(argv) {
  const options = {
    campaign: null,
    list: null,
    tests: null,
    rules: null,
    baseline: null,
    out: null,
    jobs: 3,
    threads: 2,
    timeout: 900,
    aloneLimit: 40,
    build: true,
    dryRun: false,
  };
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = () => {
      index += 1;
      if (index >= argv.length) fail(`${argument} needs a value`);
      return argv[index];
    };
    if (argument === '--tests') options.tests = value().split(',').filter(Boolean);
    else if (argument === '--rules') options.rules = value().split(',').filter(Boolean);
    else if (argument === '--baseline') options.baseline = path.resolve(value());
    else if (argument === '--out') options.out = path.resolve(value());
    else if (argument === '--jobs') options.jobs = Number(value());
    else if (argument === '--threads') options.threads = Number(value());
    else if (argument === '--timeout') options.timeout = Number(value());
    else if (argument === '--alone-limit') options.aloneLimit = Number(value());
    else if (argument === '--no-build') options.build = false;
    else if (argument === '--dry-run') options.dryRun = true;
    else if (argument.startsWith('--')) fail(`unknown option ${argument}`);
    else positional.push(argument);
  }
  [options.campaign, options.list] = positional;
  if (!['rules', 'artifacts'].includes(options.campaign)) {
    fail('usage: node tools/mutation-run.mjs rules|artifacts [list.json] [options]');
  }
  if (options.campaign === 'artifacts' && !options.list) fail('artifacts needs a list file');
  if (!(options.jobs >= 1 && options.jobs <= 3)) fail('--jobs is 1, 2 or 3');
  // With one test thread the test runner does not name the thread after the test, and the
  // result lines lose the name of their test.
  if (!(options.threads >= 2)) fail('--threads is at least 2');
  if (!(options.timeout > 0)) fail('--timeout is a number of seconds');
  if (!(options.aloneLimit >= 0)) fail('--alone-limit is a number of cases');
  const target = process.env.CARGO_TARGET_DIR
    ? path.resolve(process.env.CARGO_TARGET_DIR)
    : path.join(ROOT, 'target');
  options.target = target;
  options.baseline ??= path.join(target, 'check-results');
  options.out ??= path.join(target, 'mutation');
  return options;
}

function fail(message) {
  console.error(`mutation-run: ${message}`);
  process.exit(2);
}

// ---------------------------------------------------------------------------------------
// The test executables

function executablesFromCargo(names) {
  const args = ['test', '--frozen', '-p', 'checks', '--no-run', '--message-format=json'];
  for (const name of names ?? []) args.push('--test', name);
  const cargo = spawnSync('cargo', args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 1 << 29,
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  if (cargo.error) return { error: `cargo could not be started: ${cargo.error.message}` };
  const executables = {};
  for (const line of cargo.stdout.split('\n')) {
    if (!line.startsWith('{')) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue;
    }
    if (message.reason !== 'compiler-artifact' || !message.executable) continue;
    if (!message.target?.kind?.includes('test')) continue;
    executables[message.target.name] = message.executable;
  }
  if (cargo.status !== 0) {
    return { error: `cargo test --no-run ended with status ${cargo.status}`, executables };
  }
  return { executables };
}

function executablesFromScan(target) {
  const deps = path.join(target, 'debug', 'deps');
  const newest = {};
  for (const file of fs.existsSync(deps) ? fs.readdirSync(deps) : []) {
    const match = /^(.+)-[0-9a-f]{16}(\.exe)?$/.exec(file);
    if (!match || (process.platform === 'win32' && !match[2])) continue;
    const full = path.join(deps, file);
    const stat = fs.statSync(full);
    if (!stat.isFile()) continue;
    if (!newest[match[1]] || newest[match[1]].time < stat.mtimeMs) {
      newest[match[1]] = { time: stat.mtimeMs, path: full };
    }
  }
  return Object.fromEntries(Object.entries(newest).map(([name, entry]) => [name, entry.path]));
}

// ---------------------------------------------------------------------------------------
// Result files

function readLines(file) {
  if (!fs.existsSync(file)) return [];
  const lines = [];
  for (const text of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!text.trim()) continue;
    try {
      lines.push(JSON.parse(text));
    } catch {
      lines.push({ unreadable: true });
    }
  }
  return lines;
}

// The cases of a set of result lines, keyed by binary and case id. A case id that was
// recorded more than once keeps its lines in file order: the n-th line of a later run is
// held against the n-th line of the baseline.
function casesOf(lines) {
  const cases = new Map();
  for (const line of lines) {
    if (line.unreadable || line.kind === 'structural' || !Array.isArray(line.inputs)) continue;
    const key = `${line.binary}::${line.case}`;
    if (!cases.has(key)) cases.set(key, []);
    cases.get(key).push(line);
  }
  return cases;
}

function readBaseline(options) {
  if (!fs.existsSync(options.baseline)) fail(`no baseline at ${options.baseline}`);
  const baseline = { files: {}, lines: [], structural: 0, unreadable: 0, fromMutationRun: 0 };
  for (const file of fs.readdirSync(options.baseline).sort()) {
    if (!file.endsWith('.jsonl')) continue;
    const name = file.slice(0, -'.jsonl'.length);
    if (options.tests && !options.tests.includes(name)) continue;
    const lines = readLines(path.join(options.baseline, file));
    baseline.files[name] = lines.length;
    for (const line of lines) {
      if (line.unreadable) baseline.unreadable += 1;
      else if (line.mutation) baseline.fromMutationRun += 1;
      else if (line.kind === 'structural') baseline.structural += 1;
      else if (Array.isArray(line.inputs)) baseline.lines.push(line);
    }
  }
  baseline.cases = casesOf(baseline.lines);
  baseline.duplicates = [...baseline.cases].filter(([, lines]) => lines.length > 1).map(([key]) => key);
  return baseline;
}

// The run of an input that both a full and a fast run make: by itself, without a limit.
function stopOf(input) {
  const run = input?.alone;
  if (!run) return { ran: false };
  if (run.ok) return { ran: true, ok: true };
  const refusal = run.refusal ?? {};
  return {
    ran: true,
    ok: false,
    error: run.error?.variant ?? null,
    refused_by: refusal.refused_by ?? null,
    rule: refusal.rule ?? null,
    at_rule: refusal.at_rule ?? null,
    part: refusal.part ?? null,
    contract: refusal.contract ?? null,
    byte_offset: refusal.byte_offset ?? null,
    opcode: refusal.opcode ?? null,
    line: refusal.sil?.line ?? null,
  };
}

function scriptVerdict(line) {
  if (!Array.isArray(line.inputs) || line.scripts?.not_run) return 'not_run';
  const stops = line.inputs.map(stopOf);
  if (stops.some((stop) => !stop.ran)) return 'not_run';
  return stops.every((stop) => stop.ok) ? 'accept' : 'refuse';
}

// ---------------------------------------------------------------------------------------
// Running test executables

class Pool {
  constructor(size) {
    this.size = size;
    this.active = 0;
    this.queue = [];
  }
  run(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this.next();
    });
  }
  next() {
    while (this.active < this.size && this.queue.length > 0) {
      const { task, resolve, reject } = this.queue.shift();
      this.active += 1;
      task()
        .then(resolve, reject)
        .finally(() => {
          this.active -= 1;
          this.next();
        });
    }
  }
}

// Starts one test executable and waits for it. Output goes to two files next to the
// result file; the exit status and a timeout are returned, never dropped.
function runExecutable(executable, binary, tests, variables, directory, options) {
  return new Promise((resolve) => {
    fs.mkdirSync(directory, { recursive: true });
    const args = [];
    // A command line has a length limit; beyond it the whole binary runs.
    if (tests && tests.length > 0 && tests.join(' ').length < 20000) args.push(...tests, '--exact');
    args.push(`--test-threads=${options.threads}`);
    const env = { ...process.env };
    for (const name of MODE_VARIABLES) delete env[name];
    Object.assign(env, variables, { CHECK_RESULTS_DIR: directory });
    const stdout = fs.openSync(path.join(directory, `${binary}.stdout.txt`), 'w');
    const stderr = fs.openSync(path.join(directory, `${binary}.stderr.txt`), 'w');
    const started = Date.now();
    const child = spawn(executable, args, { cwd: ROOT, env, stdio: ['ignore', stdout, stderr] });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, options.timeout * 1000);
    const finish = (exitCode, problem) => {
      clearTimeout(timer);
      fs.closeSync(stdout);
      fs.closeSync(stderr);
      resolve({
        binary,
        exit_code: exitCode,
        timed_out: timedOut,
        problem: problem ?? null,
        seconds: (Date.now() - started) / 1000,
        tests: args.includes('--exact') ? tests.length : 'all',
      });
    };
    child.on('error', (error) => finish(null, error.message));
    child.on('close', (code, signal) => finish(code, signal ? `ended by ${signal}` : null));
  });
}

// Runs the binaries of one mutant and returns the lines they wrote, as cases.
async function runMutant(pool, executables, binaries, variables, directory, options) {
  const processes = await Promise.all(
    [...binaries].map(([binary, tests]) =>
      pool.run(() => {
        const executable = executables[binary];
        if (!executable) {
          return Promise.resolve({ binary, exit_code: null, timed_out: false, problem: 'no test executable', seconds: 0 });
        }
        return runExecutable(executable, binary, tests, variables, directory, options);
      }),
    ),
  );
  const lines = [];
  for (const [binary] of binaries) lines.push(...readLines(path.join(directory, `${binary}.jsonl`)));
  return { processes, cases: casesOf(lines) };
}

// A first pass leaves a case without a line when its test stops before it gets there, at
// an assertion of its own: about an outcome of the fast mode, about the placeholder of a
// case that was not selected, or about an earlier case under the mutant. Such cases are
// run again, twice if need be:
//   pass 2  their tests once more in full (every evaluation; with a case list, the other
//           cases as an ordinary run has them), one executable per binary;
//   pass 3  each case still missing by itself, in full, the cases in front of it as an
//           ordinary run has them (CHECKS_UNSELECTED=pinned). At most --alone-limit cases
//           per mutant: every one of them runs its whole test again.
// `need(key)` is the number of lines of the case that are wanted, `selection` the case
// list of pass 2. Returns the lines found by case key with the pass that found them.
async function repeatMissing(pool, executables, missing, linesOf, need, variables, selection, directory, options) {
  const found = new Map();
  const processes = [];
  const report = { found, processes, repeated_in_full: missing.length, repeated_alone: 0, not_repeated_alone: 0 };
  if (missing.length === 0) return report;

  const second = await runMutant(
    pool,
    executables,
    binariesOf(missing.flatMap(linesOf)),
    { ...variables, CHECKS_OBSERVE: '1', ...selection },
    path.join(directory, 'pass2'),
    options,
  );
  processes.push(...second.processes.map((item) => ({ ...item, pass: 2 })));
  for (const key of missing) {
    if (second.cases.has(key)) found.set(key, { lines: second.cases.get(key), pass: 2 });
  }

  const still = missing.filter((key) => (found.get(key)?.lines.length ?? 0) < need(key));
  const alone = still.slice(0, options.aloneLimit);
  report.repeated_alone = alone.length;
  report.not_repeated_alone = still.length - alone.length;
  await Promise.all(
    alone.map(async (key, index) => {
      const folder = path.join(directory, 'pass3', String(index + 1));
      fs.mkdirSync(folder, { recursive: true });
      const list = path.join(folder, 'cases.txt');
      fs.writeFileSync(list, key + '\n');
      const third = await runMutant(
        pool,
        executables,
        binariesOf(linesOf(key)),
        { ...variables, CHECKS_OBSERVE: '1', CHECKS_ONLY_CASES: list, CHECKS_UNSELECTED: 'pinned' },
        folder,
        options,
      );
      processes.push(...third.processes.map((item) => ({ ...item, pass: 3, case: key })));
      const lines = third.cases.get(key);
      if (lines && lines.length > (found.get(key)?.lines.length ?? 0)) found.set(key, { lines, pass: 3 });
    }),
  );
  return report;
}

// The test functions to run for a set of baseline lines, per binary. `null` for a binary
// with a line that does not name its test: the whole binary runs then.
function binariesOf(lines) {
  const binaries = new Map();
  for (const line of lines) {
    if (!binaries.has(line.binary)) binaries.set(line.binary, new Set());
    const tests = binaries.get(line.binary);
    if (tests === null) continue;
    if (line.test) tests.add(line.test);
    else binaries.set(line.binary, null);
  }
  return new Map([...binaries].map(([binary, tests]) => [binary, tests && [...tests].sort()]));
}

// ---------------------------------------------------------------------------------------
// The rules campaign

function readInventory() {
  const file = path.join(ROOT, 'data', 'rule-inventory.json');
  const inventory = JSON.parse(fs.readFileSync(file, 'utf8'));
  return inventory.rules.map((rule) => ({
    rule_id: rule.rule_id,
    contract: rule.contract,
    entry: rule.entry,
    check_opcode: rule.check_opcode ?? null,
    offsets: Array.isArray(rule.bytecode_at) ? rule.bytecode_at : [],
    origin: rule.origin ?? null,
  }));
}

// What happened to one baseline refusal under the mutant.
function classify(baselineStop, mutantLine, inputIndex) {
  if (!mutantLine) return { class: 'not_run', detail: 'the case wrote no line' };
  const stops = mutantLine.inputs.map(stopOf);
  const stop = stops[inputIndex];
  if (!stop || !stop.ran) {
    return { class: 'not_run', detail: mutantLine.scripts?.not_run ?? 'the input was not run' };
  }
  if (stop.ok) {
    const elsewhere = stops.findIndex((other) => other.ran && !other.ok);
    if (elsewhere === -1) return { class: 'now_accepted' };
    const other = stops[elsewhere];
    return {
      class: 'refused_at_another_input',
      input: elsewhere,
      by: other.rule ?? other.refused_by ?? other.error,
      error: other.error,
    };
  }
  if (stop.contract === baselineStop.contract && stop.byte_offset === baselineStop.byte_offset && stop.part === baselineStop.part) {
    return { class: 'unchanged', by: stop.refused_by, error: stop.error };
  }
  if (stop.rule) return { class: 'refused_by_another_rule', by: stop.rule, error: stop.error, line: stop.line };
  return {
    class: 'refused_by_the_engine',
    by: stop.refused_by ?? stop.error,
    error: stop.error,
    at_rule: stop.at_rule,
    part: stop.part,
    byte_offset: stop.byte_offset,
  };
}

async function rulesCampaign(options, baseline, executables) {
  const rules = readInventory();
  const byPlace = new Map();
  for (const rule of rules) {
    for (const offset of rule.offsets) byPlace.set(`${rule.contract}@${offset}`, rule);
  }

  // Every refusal of the baseline that stopped at an opcode of a contract script.
  const hits = new Map();
  const outside = new Map();
  for (const [key, lines] of baseline.cases) {
    lines.forEach((line, occurrence) => {
      line.inputs.forEach((input, inputIndex) => {
        const stop = stopOf(input);
        if (!stop.ran || stop.ok || stop.part !== 'contract_script' || stop.byte_offset === null) return;
        const place = `${stop.contract}@${stop.byte_offset}`;
        const hit = { key, occurrence, line, input: inputIndex, stop };
        const bucket = byPlace.has(place) ? hits : outside;
        if (!bucket.has(place)) bucket.set(place, []);
        bucket.get(place).push(hit);
      });
    });
  }

  const wanted = (rule) => !options.rules || options.rules.includes(rule.rule_id);
  const report = [];
  const plan = [];
  for (const rule of rules.filter(wanted)) {
    const entry = { ...rule, cases: 0, status: null, mutants: [] };
    const places = rule.offsets.map((offset) => `${rule.contract}@${offset}`);
    entry.cases = places.reduce((sum, place) => sum + (hits.get(place)?.length ?? 0), 0);
    entry.offsets_without_case = rule.offsets.filter((offset) => !hits.has(`${rule.contract}@${offset}`));
    if (entry.cases === 0) entry.status = 'uncovered';
    else if (!NEUTRALISED[rule.check_opcode]) entry.status = 'not_mutable';
    else {
      for (const place of places.filter((place) => hits.has(place))) {
        const mutant = { label: place, hits: hits.get(place), results: [], processes: [], seconds: 0 };
        entry.mutants.push(mutant);
        plan.push({ entry, mutant });
      }
    }
    report.push(entry);
  }

  console.log(
    `rules campaign: ${plan.length} mutants over ${report.filter((rule) => rule.mutants.length).length} rules, ` +
      `${plan.reduce((sum, { mutant }) => sum + mutant.hits.length, 0)} refusals to repeat`,
  );
  if (options.dryRun) {
    for (const { entry, mutant } of plan) console.log(`  ${entry.rule_id.padEnd(5)} ${mutant.label.padEnd(18)} ${mutant.hits.length} cases`);
    return null;
  }

  const pool = new Pool(options.jobs);
  let done = 0;
  await Promise.all(
    plan.map(async ({ entry, mutant }) => {
      const directory = path.join(options.out, 'rules', mutant.label.replace('@', '-at-'));
      fs.rmSync(directory, { recursive: true, force: true });
      fs.mkdirSync(directory, { recursive: true });
      const list = path.join(directory, 'cases.txt');
      const keys = [...new Set(mutant.hits.map((hit) => hit.key))];
      fs.writeFileSync(list, keys.join('\n') + '\n');
      const first = await runMutant(
        pool,
        executables,
        binariesOf(mutant.hits.map((hit) => hit.line)),
        { CHECKS_MUTANT: mutant.label, CHECKS_OBSERVE: '1', CHECKS_FAST: '1', CHECKS_ONLY_CASES: list },
        directory,
        options,
      );
      mutant.processes.push(...first.processes.map((process) => ({ ...process, pass: 1 })));
      let found = first.cases;

      const missing = [...new Set(mutant.hits.filter((hit) => !found.get(hit.key)?.[hit.occurrence]).map((hit) => hit.key))];
      const hitsOf = (key) => mutant.hits.filter((hit) => hit.key === key);
      const repeated = await repeatMissing(
        pool,
        executables,
        missing,
        (key) => hitsOf(key).map((hit) => hit.line),
        (key) => Math.max(...hitsOf(key).map((hit) => hit.occurrence)) + 1,
        { CHECKS_MUTANT: mutant.label },
        { CHECKS_ONLY_CASES: list, CHECKS_UNSELECTED: 'pinned' },
        directory,
        options,
      );
      mutant.processes.push(...repeated.processes);
      mutant.repeated_in_full = repeated.repeated_in_full;
      mutant.repeated_alone = repeated.repeated_alone;
      mutant.not_repeated_alone = repeated.not_repeated_alone;
      const second = repeated.found;

      for (const hit of mutant.hits) {
        let line = found.get(hit.key)?.[hit.occurrence];
        let pass = 1;
        if (!line && second.has(hit.key)) {
          line = second.get(hit.key).lines[hit.occurrence];
          pass = second.get(hit.key).pass;
        }
        const result = classify(hit.stop, line, hit.input);
        mutant.results.push({
          binary: hit.line.binary,
          test: hit.line.test ?? null,
          case: hit.line.case,
          occurrence: hit.occurrence,
          input: hit.input,
          py_ids: hit.line.py_ids ?? [],
          baseline: { refused_by: hit.stop.refused_by, error: hit.stop.error, rule: hit.stop.rule, line: hit.stop.line },
          pass,
          ...result,
        });
      }
      // The time its test executables ran; the wait for a free slot is not part of it.
      mutant.seconds = mutant.processes.reduce((sum, item) => sum + item.seconds, 0);
      delete mutant.hits;
      done += 1;
      const counts = countClasses(mutant.results);
      console.log(
        `  [${done}/${plan.length}] ${entry.rule_id.padEnd(5)} ${mutant.label.padEnd(18)} ` +
          `${mutant.results.length} cases in ${mutant.seconds.toFixed(1)} s: ${describeCounts(counts)}`,
      );
    }),
  );

  for (const entry of report) {
    if (entry.mutants.length === 0) continue;
    entry.counts = countClasses(entry.mutants.flatMap((mutant) => mutant.results));
    entry.backers = backersOf(entry.mutants.flatMap((mutant) => mutant.results));
    // A flagged case says nothing about the rule; the rule is filed by its other cases.
    const flags = entry.counts.unchanged + entry.counts.not_run;
    entry.flagged = flags > 0;
    if (entry.counts.now_accepted) entry.status = 'only_guard';
    else if (flags < entry.cases) entry.status = 'always_backed';
    else entry.status = 'no_answer';
  }
  const stopsWithoutRule = [...outside].map(([place, list]) => ({
    place,
    cases: list.length,
    refused_by: [...new Set(list.map((hit) => hit.stop.refused_by))],
  }));
  return { rules: report, stops_without_rule: stopsWithoutRule };
}

const CLASSES = [
  'now_accepted',
  'refused_by_another_rule',
  'refused_by_the_engine',
  'refused_at_another_input',
  'unchanged',
  'not_run',
];

function countClasses(results) {
  const counts = Object.fromEntries(CLASSES.map((name) => [name, 0]));
  for (const result of results) counts[result.class] += 1;
  return counts;
}

function describeCounts(counts) {
  const parts = CLASSES.filter((name) => counts[name] > 0).map((name) => `${counts[name]} ${name.replaceAll('_', ' ')}`);
  return parts.join(', ') || 'nothing';
}

function backersOf(results) {
  const backers = {};
  for (const result of results) {
    if (!result.by || result.class === 'unchanged') continue;
    const name = result.class === 'refused_at_another_input' ? `${result.by} (input ${result.input})` : result.by;
    backers[name] = (backers[name] ?? 0) + 1;
  }
  return backers;
}

function rulesTable(result, processes) {
  const rules = result.rules;
  const out = [];
  const row = (cells, widths) => cells.map((cell, index) => String(cell).padEnd(widths[index])).join(' ').trimEnd();
  const widths = [6, 22, 17, 5, 8, 6, 6, 6, 6, 6];
  out.push('Rules whose refusing opcode was neutralised');
  out.push(row(['rule', 'mutants', 'opcode', 'cases', 'accepted', 'rule', 'engine', 'input', 'same', 'no run', 'then refused by'], [...widths, 0]));
  for (const rule of rules.filter((rule) => rule.mutants.length > 0)) {
    const counts = rule.counts;
    out.push(
      row(
        [
          rule.rule_id,
          rule.mutants.map((mutant) => mutant.label).join(' '),
          rule.check_opcode,
          rule.cases,
          counts.now_accepted,
          counts.refused_by_another_rule,
          counts.refused_by_the_engine,
          counts.refused_at_another_input,
          counts.unchanged,
          counts.not_run,
          Object.entries(rule.backers).map(([name, count]) => `${name} x${count}`).join(', ') || '-',
        ],
        [...widths, 0],
      ),
    );
  }
  out.push('  accepted: the whole transaction passes; rule / engine: the same input is refused by another rule,');
  out.push('  by the engine; input: the input passes, another input of the transaction is refused;');
  out.push('  same: refused at the neutralised opcode (the case did not run on the mutant); no run: the case left no line.');
  out.push('');
  const group = (status) => rules.filter((rule) => rule.status === status);
  const ids = (list) => list.map((rule) => rule.rule_id).join(' ') || '-';
  const only = group('only_guard');
  out.push(`The only guard in at least one case (${only.length}): ${ids(only)}`);
  for (const rule of only) {
    for (const mutant of rule.mutants) {
      for (const item of mutant.results.filter((item) => item.class === 'now_accepted')) {
        out.push(`  ${rule.rule_id} ${mutant.label}: ${item.binary}::${item.case} (input ${item.input})`);
      }
    }
  }
  out.push(`Always backed by another refusal in the cases of the baseline (${group('always_backed').length}): ${ids(group('always_backed'))}`);
  out.push(`No answer, every case unchanged or not run (${group('no_answer').length}): ${ids(group('no_answer'))}`);
  const flagged = rules.filter((rule) => rule.flagged);
  out.push(`Rules with a flagged case, unchanged or not run (${flagged.length}): ${ids(flagged)}`);
  for (const rule of flagged) {
    for (const mutant of rule.mutants) {
      for (const item of mutant.results.filter((item) => ['unchanged', 'not_run'].includes(item.class))) {
        out.push(`  ${rule.rule_id} ${mutant.label}: ${item.class} ${item.binary}::${item.case} (input ${item.input}) ${item.detail ?? item.by ?? ''}`);
      }
    }
  }
  const uncovered = group('uncovered');
  out.push(`No case of the baseline stops there (${uncovered.length}): ${ids(uncovered)}`);
  const fixed = group('not_mutable');
  out.push(`Covered, refusing opcode is none of the three (${fixed.length}): ${fixed.map((rule) => `${rule.rule_id}:${rule.check_opcode}`).join(' ') || '-'}`);
  const partly = rules.filter((rule) => rule.cases > 0 && rule.offsets_without_case.length > 0);
  if (partly.length > 0) {
    out.push(`Covered at some of their opcodes only: ${partly.map((rule) => `${rule.rule_id} (not at ${rule.offsets_without_case.join(', ')})`).join('; ')}`);
  }
  if (result.stops_without_rule.length > 0) {
    out.push(`Baseline refusals at contract opcodes outside the rules' own offsets (not replaced; the copies under also_reached_from are among them): ${result.stops_without_rule.map((stop) => `${stop.place} x${stop.cases}`).join(', ')}`);
  }
  out.push('');
  const mutants = rules.flatMap((rule) => rule.mutants);
  const all = countClasses(mutants.flatMap((mutant) => mutant.results));
  const seconds = mutants.map((mutant) => mutant.seconds);
  out.push(`Totals: ${rules.length} rules, ${mutants.length} mutants, ${mutants.reduce((sum, mutant) => sum + mutant.results.length, 0)} repeated refusals: ${describeCounts(all)}`);
  if (seconds.length > 0) {
    out.push(`Time per mutant: mean ${(seconds.reduce((a, b) => a + b, 0) / seconds.length).toFixed(1)} s, longest ${Math.max(...seconds).toFixed(1)} s`);
  }
  const sum = (name) => mutants.reduce((total, mutant) => total + (mutant[name] ?? 0), 0);
  out.push(
    `Cases without a line after the first pass: ${sum('repeated_in_full')} (their tests repeated in full), ` +
      `${sum('repeated_alone')} of them then repeated one by one, ${sum('not_repeated_alone')} left out by --alone-limit`,
  );
  out.push(...processLines(processes));
  return out.join('\n');
}

// ---------------------------------------------------------------------------------------
// The artifacts campaign

async function artifactsCampaign(options, baseline, executables) {
  const listFile = path.resolve(options.list);
  const list = JSON.parse(fs.readFileSync(listFile, 'utf8'));
  if (!Array.isArray(list)) fail(`${listFile} is not a list`);
  const mutants = list.map((item, index) => {
    const artifact = item.artifact ?? item.path ?? item.artifact_path;
    if (!item.id || !artifact) fail(`${listFile}: entry ${index} needs "id" and "artifact"`);
    const file = path.resolve(path.dirname(listFile), artifact);
    if (!fs.existsSync(file)) fail(`${listFile}: entry ${item.id}: no file ${file}`);
    return { id: String(item.id), artifact: file, contracts: item.contracts ?? item.contracts_touched ?? [] };
  });
  const binaries = binariesOf(baseline.lines);
  console.log(`artifacts campaign: ${mutants.length} artifacts, ${baseline.lines.length} cases of ${binaries.size} binaries each`);
  if (options.dryRun) return null;

  const pool = new Pool(options.jobs);
  const report = [];
  for (const mutant of mutants) {
    const directory = path.join(options.out, 'artifacts', mutant.id.replace(/[^A-Za-z0-9._-]/g, '_'));
    fs.rmSync(directory, { recursive: true, force: true });
    const started = Date.now();
    const run = await runMutant(pool, executables, binaries, { CHECKS_ARTIFACT: mutant.artifact, CHECKS_OBSERVE: '1', CHECKS_FAST: '1' }, directory, options);
    const entry = { ...mutant, flips: [], not_run: [], same_verdict: 0, refused_elsewhere: 0, processes: run.processes, seconds: 0 };
    const judged = (key) => baseline.cases.get(key).map((line, occurrence) => ({ line, occurrence })).filter(({ line }) => scriptVerdict(line) !== 'not_run');
    const missing = [...baseline.cases.keys()].filter((key) => judged(key).some(({ occurrence }) => !run.cases.get(key)?.[occurrence]));
    const repeated = await repeatMissing(
      pool,
      executables,
      missing,
      (key) => baseline.cases.get(key),
      (key) => baseline.cases.get(key).length,
      { CHECKS_ARTIFACT: mutant.artifact },
      {},
      directory,
      options,
    );
    entry.processes.push(...repeated.processes);
    entry.repeated_in_full = repeated.repeated_in_full;
    entry.repeated_alone = repeated.repeated_alone;
    entry.not_repeated_alone = repeated.not_repeated_alone;
    for (const [key, lines] of baseline.cases) {
      lines.forEach((line, occurrence) => {
        const before = scriptVerdict(line);
        if (before === 'not_run') return;
        const now = run.cases.get(key)?.[occurrence] ?? repeated.found.get(key)?.lines[occurrence];
        const after = now ? scriptVerdict(now) : 'not_run';
        const where = { binary: line.binary, test: line.test ?? null, case: line.case, occurrence, py_ids: line.py_ids ?? [] };
        if (after === 'not_run') entry.not_run.push({ ...where, detail: now?.scripts?.not_run ?? 'the case wrote no line' });
        else if (before !== after) {
          const refusals = (now.inputs ?? line.inputs)
            .map(stopOf)
            .map((stop, input) => ({ input, ...stop }))
            .filter((stop) => stop.ran && !stop.ok)
            .map((stop) => ({ input: stop.input, by: stop.rule ?? stop.refused_by ?? stop.error, error: stop.error }));
          const lost = line.inputs
            .map(stopOf)
            .map((stop, input) => ({ input, ...stop }))
            .filter((stop) => stop.ran && !stop.ok)
            .map((stop) => ({ input: stop.input, by: stop.rule ?? stop.refused_by ?? stop.error, error: stop.error }));
          entry.flips.push({ ...where, before, after, baseline_refusals: lost, refusals: after === 'refuse' ? refusals : [] });
        } else {
          entry.same_verdict += 1;
          const place = (stops) => JSON.stringify(stops.map((stop) => [stop.ok, stop.rule ?? stop.refused_by ?? stop.error]));
          if (after === 'refuse' && place(line.inputs.map(stopOf)) !== place(now.inputs.map(stopOf))) entry.refused_elsewhere += 1;
        }
      });
    }
    entry.seconds = (Date.now() - started) / 1000;
    report.push(entry);
    console.log(
      `  ${mutant.id}: ${entry.flips.length} flips (${entry.flips.filter((flip) => flip.after === 'accept').length} now accepted), ` +
        `${entry.not_run.length} not run, ${entry.same_verdict} as before, in ${entry.seconds.toFixed(1)} s`,
    );
  }
  return { artifacts: report };
}

function artifactsTable(result, processes) {
  const out = ['Artifacts: cases whose script verdict flipped'];
  for (const entry of result.artifacts) {
    const accepted = entry.flips.filter((flip) => flip.after === 'accept');
    const refused = entry.flips.filter((flip) => flip.after === 'refuse');
    out.push(
      `${entry.id} [${[].concat(entry.contracts).join(', ')}]: ${accepted.length} now accepted, ${refused.length} now refused, ` +
        `${entry.not_run.length} not run, ${entry.same_verdict} as before (${entry.refused_elsewhere} of them refused elsewhere), ` +
        `${entry.repeated_in_full} cases repeated in full, ${entry.repeated_alone} by themselves, ${entry.seconds.toFixed(1)} s`,
    );
    for (const flip of accepted) {
      out.push(`  now accepted: ${flip.binary}::${flip.case} (was refused by ${flip.baseline_refusals.map((item) => `${item.by} at input ${item.input}`).join(', ')})`);
    }
    for (const flip of refused) {
      out.push(`  now refused:  ${flip.binary}::${flip.case} (${flip.refusals.map((item) => `${item.by} at input ${item.input}`).join(', ')})`);
    }
    for (const item of entry.not_run) out.push(`  not run:      ${item.binary}::${item.case} (${item.detail})`);
  }
  out.push('');
  const killed = result.artifacts.filter((entry) => entry.flips.length > 0).length;
  out.push(`Totals: ${result.artifacts.length} artifacts, ${killed} with at least one flipped case, ${result.artifacts.length - killed} with none`);
  out.push(...processLines(processes));
  return out.join('\n');
}

// ---------------------------------------------------------------------------------------
// Reporting

// Exit statuses and timeouts. A test executable that observes still ends with a failure
// when a test fails at an assertion of its own, so a non-zero status is common; it is
// listed all the same.
function processLines(processes) {
  const out = [];
  const timeouts = processes.filter((process) => process.timed_out);
  const problems = processes.filter((process) => process.problem && !process.timed_out);
  const failed = processes.filter((process) => process.exit_code !== 0 && !process.timed_out && !process.problem);
  out.push(`Test executables started: ${processes.length}; ended with a failure status: ${failed.length}; timed out: ${timeouts.length}; not started or killed: ${problems.length}`);
  for (const process of timeouts) out.push(`  TIMEOUT ${process.mutant} ${process.binary} after ${process.seconds.toFixed(0)} s`);
  for (const process of problems) out.push(`  PROBLEM ${process.mutant} ${process.binary}: ${process.problem}`);
  const byBinary = {};
  for (const process of failed) byBinary[process.binary] = (byBinary[process.binary] ?? 0) + 1;
  for (const [binary, count] of Object.entries(byBinary)) {
    out.push(`  failure status: ${binary} in ${count} runs (a test stopped at an assertion of its own; see <mutant>/${binary}.stdout.txt)`);
  }
  return out;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const started = new Date();
  const baseline = readBaseline(options);
  const names = Object.keys(baseline.files);
  console.log(`baseline ${options.baseline}: ${baseline.lines.length} cases in ${names.length} files (${names.join(', ')})`);
  if (baseline.fromMutationRun > 0) {
    console.log(`  ${baseline.fromMutationRun} lines come from a mutation run and are left out: a baseline is an ordinary run`);
  }
  if (baseline.lines.length === 0) fail('the baseline holds no case');

  let executables = {};
  let executablesFrom = 'cargo';
  if (!options.dryRun) {
    if (options.build) {
      const found = executablesFromCargo(names);
      if (found.error) {
        console.log(`  ${found.error}; taking the newest executables of ${path.join(options.target, 'debug', 'deps')}`);
        executables = { ...executablesFromScan(options.target), ...(found.executables ?? {}) };
        executablesFrom = `scan (${found.error})`;
      } else executables = found.executables;
    } else {
      executables = executablesFromScan(options.target);
      executablesFrom = 'scan (--no-build)';
    }
    const absent = names.filter((name) => !executables[name]);
    if (absent.length > 0) console.log(`  no test executable for: ${absent.join(', ')}`);
  }

  const result = options.campaign === 'rules'
    ? await rulesCampaign(options, baseline, executables)
    : await artifactsCampaign(options, baseline, executables);
  if (!result) return;

  const mutants = result.rules ? result.rules.flatMap((rule) => rule.mutants) : result.artifacts;
  const processes = mutants.flatMap((mutant) => mutant.processes.map((process) => ({ mutant: mutant.label ?? mutant.id, ...process })));
  const finished = new Date();
  const summary = {
    campaign: options.campaign,
    started: started.toISOString(),
    finished: finished.toISOString(),
    seconds: (finished - started) / 1000,
    options: { tests: options.tests, rules: options.rules, jobs: options.jobs, threads: options.threads, timeout: options.timeout, alone_limit: options.aloneLimit, list: options.list },
    baseline: {
      directory: options.baseline,
      files: baseline.files,
      cases: baseline.lines.length,
      structural_lines: baseline.structural,
      unreadable_lines: baseline.unreadable,
      lines_of_a_mutation_run_left_out: baseline.fromMutationRun,
      case_ids_recorded_more_than_once: baseline.duplicates,
    },
    executables_from: executablesFrom,
    executables: Object.fromEntries(names.map((name) => [name, executables[name] ?? null])),
    processes: {
      started: processes.length,
      failure_status: processes.filter((process) => process.exit_code !== 0 && !process.timed_out && !process.problem).length,
      timed_out: processes.filter((process) => process.timed_out),
      problems: processes.filter((process) => process.problem && !process.timed_out),
    },
    ...result,
  };
  const table = (result.rules ? rulesTable(result, processes) : artifactsTable(result, processes)) +
    `\nWhole run: ${summary.seconds.toFixed(0)} s, at most ${options.jobs} test executables at a time\n`;
  fs.mkdirSync(options.out, { recursive: true });
  const jsonFile = path.join(options.out, `${options.campaign}-summary.json`);
  const textFile = path.join(options.out, `${options.campaign}-summary.txt`);
  fs.writeFileSync(jsonFile, JSON.stringify(summary, null, 1) + '\n');
  fs.writeFileSync(textFile, table);
  console.log('');
  console.log(table);
  console.log(`written: ${jsonFile}`);
  console.log(`         ${textFile}`);
  if (summary.processes.timed_out.length > 0 || summary.processes.problems.length > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
