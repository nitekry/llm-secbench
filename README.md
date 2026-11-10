# llm-secbench

A small, self-scoring benchmark for how well a **local LLM** handles defensive security work: auditing code for vulnerabilities and triaging attack logs. It talks to any OpenAI-compatible chat endpoint (llama.cpp `llama-server`, Ollama, vLLM, LM Studio, ...), runs unattended, and writes a scored report.

All tasks were written for this project (Nov 2026) or are generated from a seed. None are copied from public CTFs or CVE write-ups, so a model can't score by remembering answers.

> ⚠️ `src/code/` and the generated `tasks/` contain **deliberately vulnerable code**. It is only ever shown to the model as text. Never deploy or run it.

## Suites

### core: hand-written (32 tasks)
**Track A: code audit (24 tasks).** 12 short C, Python, JS and PHP programs, each with one real vulnerability, plus a *fixed twin* of each with the bug patched. The model reports whether the code is vulnerable, the CWE (bug type) and the line.
Bugs covered: buffer overflow, off-by-one, format string, use-after-free, integer overflow, TOCTOU race in a setuid binary, SQL injection, command injection, path traversal, pickle deserialization, IDOR, MD5 password hashing.
The twins measure false alarms. A model that calls everything vulnerable scores 50% on verdict and 0% on the twins.

**Track B: log forensics (8 tasks, ~5.5k–22k tokens).** Synthetic `auth.log` and nginx access logs. Each has normal activity, internet scanning noise, and one incident: SSH brute force (with or without success), password spray, SQL injection, path traversal, web shell, cron persistence, or SSH-key persistence. The graded fields are attacker IP, technique, first-seen time and compromised account. The logs are generated from a fixed seed by `build_tasks.py`.

### gen: procedurally generated code (32 new tasks per seed)
The core bugs are textbook shapes (`strcpy`, f-string SQL, `shell=True`). A model can find them by spotting dangerous API calls without understanding the code. `gen_code.py` separates the two skills: it has 8 families (command injection, SQL injection, path traversal, deserialization, buffer copy, integer overflow, use-after-free, IDOR), each in 4 variants.

| variant | contents | vulnerable? |
|---|---|---|
| `obvious` | bug on the dangerous-API line (textbook) | yes |
| `hidden` | same bug class, but in data flow, a bounds check or a helper (e.g. `>` vs `>=`, `dict.get(k, k)` fallback, a 16-bit sum that wraps, an unkeyed SHA-256 "integrity" check before `pickle.loads`) | yes |
| `decoy` | the dangerous API used correctly (`shell=True` + `shlex.quote`, `strcpy` after a length check, HMAC-verified pickle, ...) | **no** |
| `plain` | boring, correct code | **no** |

The domain (18 of them), identifiers, tool paths and filler helper functions are drawn from the seed, so every seed is new source text. A pattern-matcher does well on `obvious` and poorly on `hidden` and `decoy`. Average over several seeds, since one seed has only 4 tasks per variant.

## Requirements
- Python ≥ 3.8, **standard library only** (see `requirements.txt`; there's nothing to `pip install`).
- An OpenAI-compatible chat endpoint. `run.sh` starts llama.cpp's `llama-server` for you.
- bash + curl for `run.sh`.
- Optional: `gcc` and `node`. If they're installed, `gen_code.py` syntax-checks the generated C and JS.
- Context: the log track needs about 23k tokens. Run the server with ≥ 32k context.

The Flask, Express and sqlite code in the tasks is only read by the model, never executed, so those frameworks don't need to be installed.

## Quick start
```bash
# 0. offline self-test (no model needed)
python3 -m unittest discover -s tests -v

# 1a. llama.cpp: run.sh starts llama-server, runs, and stops it
MODEL=/path/to/model.gguf BIN=/path/to/llama-server bash run.sh my-model            # core suite
MODEL=... SUITE=gen SEEDS="1 2 3" bash run.sh my-model                              # generated suite
MODEL=... SUITE=all bash run.sh my-model                                            # both
#    (or put MODEL/BIN in local.env, see local.env.example)

# 1b. any other server that's already running
python3 run_bench.py --label my-model --url http://127.0.0.1:8080
python3 run_bench.py --label my-model --url http://127.0.0.1:11434 --model qwen2.5-coder:14b   # Ollama
python3 run_bench.py --label my-model --suite gen --seed 1 --url ...

# 2. reports
python3 run_bench.py --label my-model --aggregate      # mean/range over gen seeds
python3 run_bench.py --label my-model --score-only     # rescore after a scorer change
```
Task sets are built automatically on first use. To build them explicitly, run `python3 build_tasks.py` (core) or `python3 gen_code.py --seed 1 2 3` (gen). Both are deterministic, so the same seed gives byte-identical tasks on any machine and the tasks aren't committed.

Runs resume where they stopped: re-run the same command to pick up unfinished or failed tasks. Delete `results/<label>/` to start over.

Typical runtime on a Radeon 680M iGPU with a 14B Q5 model: core ≈ 40 min (the log track's long prompts dominate), gen ≈ 10 min per seed.

## Output
`results/<label>/`, plus `results/<label>/gen-s<seed>/` for each seed:
- `summary.md`: score tables plus a per-task table of expected vs actual answers
- `summary.json`: the same numbers, machine-readable
- `results.jsonl`: one line per task with the raw model output, token counts and llama.cpp timings
- `gen-aggregate.md`: averages across seeds, split by variant and family, compared against the core set

## Scoring
- All requests run at temperature 0 with `seed=1`. Answers must be a JSON object, extracted leniently (code fences and chatter are ignored). An unparseable answer counts as wrong.
- **Code: full credit** needs the correct vulnerable/safe verdict. For vulnerable samples it also needs a CWE from the accepted list for that bug, and a line within ±2 of a marked line. The report also shows precision, recall and false-alarm rate.
- **Logs:** attacker IP, technique and account are exact matches (the account accepts listed alternatives). For first-seen, the answer must contain exactly the key's `HH:MM:SS`, and any IP in it must be the attacker's, so a pasted log line from another host fails. Full credit means all four fields are correct.
- **Prompt versions:** each result records `prompt_version`. v2 (current) shuffles the technique list per task to remove list-order bias. The baseline below used v1, so compare log technique accuracy only within one version.

## Repository layout
```
build_tasks.py     core suite: code twins from src/code (+ patches/CWE keys) and the log generator
gen_code.py        gen suite: families, variants, randomization, syntax checks
run_bench.py       runner, scorer, summaries, --aggregate
run.sh             unattended llama-server wrapper
make_bundle.sh     test, bundle and copy the repo for sharing
src/code/          hand-written vulnerable sources; `@@VULN@@` marks the key line(s), stripped before prompting
tests/             offline unit tests for the scorer and generator invariants
baseline/          published reference results
```

## Sharing
`bash make_bundle.sh` runs the self-tests, writes a git bundle with the full history to `~/llm-secbench.bundle`, and puts a clean clone in `~/Documents/github/llm-secbench`. Later runs fast-forward that clone. Override the locations with `BUNDLE=...` and `DEST=...`. Only committed work is included. Recipients run `git clone llm-secbench.bundle`.

## Extending
- **New gen family:** add an entry to `F` in `gen_code.py` with `lang`, `ext`, accepted `cwe` list, a `skel` (using `${...}` placeholders) and `variants` for `obvious`, `hidden`, `decoy` and `plain`. Put `# @@VULN@@`, `// @@VULN@@` or `/* @@VULN@@ */` on the flawed line(s) of the two vulnerable variants. Make sure `decoy` and `plain` are **actually safe**, or the false-alarm metric becomes unfair. Run the tests afterwards.
- **New core sample:** drop a marked file in `src/code/` and add its accepted CWEs and fix patch to `CODE` in `build_tasks.py`.
- Don't change tasks between runs you want to compare. Rebuild on purpose and re-run everything.

## Baseline
`baseline/qwen2.5-coder-14b-q5km/` holds the core suite results for Qwen2.5-Coder-14B-Instruct (abliterated fine-tune, Q5_K_M), run on llama.cpp Vulkan with prompt v1:

| overall | code full credit | false alarms on fixed twins | logs full credit |
|---|---|---|---|
| 37.5% | 29.2% | 100% (12/12) | 62.5% |

It called every sample vulnerable. It found the bugs that sit on a dangerous call (`strcpy`, f-string SQL, `shell=True`, `pickle`, `md5`, `malloc(w*h)`) and missed every bug that needs reasoning (off-by-one, UAF, format string, TOCTOU, IDOR). On logs it identified the attacker IP and account 8/8, but labelled every SSH incident `brute_force` and sometimes invented log lines.

## Limitations
- Sample sizes are small: one core code bug is about 8 points and one log task 12.5. Treat differences under ~15 points as noise, and use several gen seeds.
- Logs are synthetic and simpler than real fleet telemetry.
- Single-turn and no tools: this measures reading comprehension, not agentic investigation.
- The model sees whole files with line numbers. There's no repository-scale context.

## License
MIT, see `LICENSE`.
