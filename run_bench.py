#!/usr/bin/env python3
"""Run (and score) the security benchmark against an OpenAI-compatible endpoint.

  python3 run_bench.py --label qwen14b-q5km                 # llama-server on :8081
  python3 run_bench.py --label q14-ollama --url http://127.0.0.1:11434 --model qwen2.5-coder:14b
  python3 run_bench.py --label qwen14b-q5km --score-only     # rescore existing results

Results go to results/<label>/: results.jsonl (one line per task, appended as it
goes, so a killed run resumes where it stopped), summary.json and summary.md.
"""
import argparse
import json
import random
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# v1: fixed technique order. v2: technique list shuffled per task (removes list-order bias).
PROMPT_VERSION = 2
TECHNIQUES = ["brute_force", "password_spray", "sqli", "path_traversal", "web_shell",
              "cron_persistence", "ssh_key_persistence"]

SYSTEM = "You are a meticulous application-security and incident-response analyst. You answer with a single JSON object and nothing else."

CODE_PROMPT = """Audit the following {lang} code for security vulnerabilities. Lines are numbered.
Some samples contain exactly one security vulnerability; others contain none. Do not report style issues, missing features, or theoretical hardening; only a concrete, exploitable flaw counts.

```
{code}
```

Respond with ONLY this JSON object:
{{"reasoning": "<at most 3 sentences>", "vulnerable": true or false, "cwe": "CWE-<number>" or null, "line": <line number of the flaw> or null, "fix": "<one sentence>" or null}}"""

LOG_PROMPT = """You are investigating a server. Below is a {fmt} covering several hours.
It contains normal activity, isolated internet background scanning (short failed probes that go nowhere; that is NOT the incident), and exactly ONE security incident by a single attacker IP.

```
{log}
```

Identify the incident. Respond with ONLY this JSON object:
{{"reasoning": "<at most 3 sentences>", "attacker_ip": "<IP>", "technique": one of {techniques}, "first_seen": "<timestamp of the attacker's earliest log line, copied as it appears in the log>", "compromised_account": "<local account the attacker gained access to, or \\"none\\">"}}"""


def number_lines(text):
    lines = text.rstrip("\n").split("\n")
    w = len(str(len(lines)))
    return "\n".join(f"{i:>{w}} | {l}" for i, l in enumerate(lines, 1))


def build_prompt(task):
    text = (ROOT / task["file"]).read_text()
    if task["track"] == "code":
        return CODE_PROMPT.format(lang=task["lang"], code=number_lines(text)), 700
    techniques = list(TECHNIQUES)
    random.Random(task["id"]).shuffle(techniques)  # deterministic per task
    return LOG_PROMPT.format(fmt=task["fmt"], log=text.rstrip("\n"), techniques=json.dumps(techniques)), 500


def chat(url, model, prompt, max_tokens, timeout):
    body = dict(messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                max_tokens=max_tokens, temperature=0, seed=1)
    if model:
        body["model"] = model
    req = urllib.request.Request(url.rstrip("/") + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.load(r)
    return resp, time.time() - t


def extract_json(text):
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text or ""):
        try:
            obj, _ = dec.raw_decode(text[m.start():])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def cwe_num(v):
    m = re.search(r"(\d+)", str(v or ""))
    return int(m.group(1)) if m else None


def as_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "yes", "1")


def as_int(v):
    try:
        return int(str(v).strip().split()[0].strip(",;"))
    except (ValueError, IndexError):
        return None


def score_task(task, ans):
    key = task["key"]
    if ans is None:
        return dict(valid=False, full=False)
    if task["track"] == "code":
        v = as_bool(ans.get("vulnerable"))
        s = dict(valid=True, said_vulnerable=v, verdict=v == key["vulnerable"])
        if key["vulnerable"]:
            line = as_int(ans.get("line"))
            s["cwe"] = v and cwe_num(ans.get("cwe")) in key["cwe"]
            s["line"] = v and line is not None and any(abs(line - k) <= 2 for k in key["lines"])
            s["full"] = s["verdict"] and s["cwe"] and s["line"]
        else:
            s["full"] = s["verdict"]
        return s
    acct = str(ans.get("compromised_account") or "none").strip().lower()
    acct = "none" if acct in ("", "null", "n/a", "none") else acct
    s = dict(
        valid=True,
        attacker_ip=str(ans.get("attacker_ip", "")).strip() == key["attacker_ip"],
        technique=str(ans.get("technique", "")).strip().lower() == key["technique"],
        first_seen=first_seen_ok(str(ans.get("first_seen", "")), key),
        account=acct in key["compromised_account"],
    )
    s["full"] = all(s[k] for k in ("attacker_ip", "technique", "first_seen", "account"))
    return s


TIME_RE = re.compile(r"\b(\d{2}:\d{2}:\d{2})\b")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def first_seen_ok(ans, key):
    """The answer must name exactly one time, equal to the key. If the model pasted a
    whole log line, every IP in it must be the attacker's (catches invented lines)."""
    times = set(TIME_RE.findall(ans))
    ips = set(IP_RE.findall(ans))
    return times == {key["first_seen"]} and ips <= {key["attacker_ip"]}


def load_results(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                out[r["id"]] = r
    return out


def summarize(tasks, results, label, outdir):
    by_id = {t["id"]: t for t in tasks}
    rs = [r for r in results.values() if r["id"] in by_id and "error" not in r]
    errors = [r for r in results.values() if "error" in r]
    for r in rs:  # rescore from raw answers so key changes apply
        r["score"] = score_task(by_id[r["id"]], extract_json(r.get("raw")))
    code = [r for r in rs if by_id[r["id"]]["track"] == "code"]
    logs = [r for r in rs if by_id[r["id"]]["track"] == "logs"]

    def pct(a, b):
        return round(100 * a / b, 1) if b else None

    tp = sum(1 for r in code if by_id[r["id"]]["key"]["vulnerable"] and r["score"].get("said_vulnerable"))
    fn = sum(1 for r in code if by_id[r["id"]]["key"]["vulnerable"] and not r["score"].get("said_vulnerable"))
    fp = sum(1 for r in code if not by_id[r["id"]]["key"]["vulnerable"] and r["score"].get("said_vulnerable"))
    tn = sum(1 for r in code if not by_id[r["id"]]["key"]["vulnerable"] and not r["score"].get("said_vulnerable"))
    vul = [r for r in code if by_id[r["id"]]["key"]["vulnerable"]]
    s = dict(
        label=label, scored_at=datetime.now().isoformat(timespec="seconds"),
        prompt_versions=sorted({r.get('prompt_version', 1) for r in rs}),
        tasks_done=len(rs), tasks_total=len(tasks), errors=len(errors),
        invalid_json=sum(1 for r in rs if not r["score"]["valid"]),
        code=dict(n=len(code), tp=tp, fp=fp, tn=tn, fn=fn,
                  verdict_acc=pct(tp + tn, len(code)), precision=pct(tp, tp + fp), recall=pct(tp, tp + fn),
                  false_alarm_rate=pct(fp, fp + tn),
                  cwe_acc=pct(sum(bool(r["score"].get("cwe")) for r in vul), len(vul)),
                  line_acc=pct(sum(bool(r["score"].get("line")) for r in vul), len(vul)),
                  full_credit=pct(sum(bool(r["score"].get("full")) for r in code), len(code))),
        logs=dict(n=len(logs), **{f"{k}_acc": pct(sum(bool(r["score"].get(k)) for r in logs), len(logs))
                                   for k in ("attacker_ip", "technique", "first_seen", "account", "full")}),
        time=dict(total_s=round(sum(r["wall_s"] for r in rs), 1),
                  prompt_tokens=sum(r.get("prompt_tokens") or 0 for r in rs),
                  completion_tokens=sum(r.get("completion_tokens") or 0 for r in rs)),
    )
    pp = [r["timings"]["prompt_per_second"] for r in rs if r.get("timings") and r["timings"].get("prompt_n", 0) > 50]
    tg = [r["timings"]["predicted_per_second"] for r in rs if r.get("timings")]
    s["time"]["avg_pp_tok_s"] = round(sum(pp) / len(pp), 1) if pp else None
    s["time"]["avg_tg_tok_s"] = round(sum(tg) / len(tg), 2) if tg else None
    s["overall_full_credit"] = pct(sum(bool(r["score"].get("full")) for r in rs), len(rs))
    if any("variant" in by_id[r["id"]]["key"] for r in code):
        s["by_variant"], s["by_family"] = {}, {}
        for field, dest in (("variant", s["by_variant"]), ("family", s["by_family"])):
            for r in code:
                k = by_id[r["id"]]["key"][field]
                d = dest.setdefault(k, dict(n=0, full=0, verdict=0))
                d["n"] += 1
                d["full"] += bool(r["score"].get("full"))
                d["verdict"] += bool(r["score"].get("verdict"))
            for d in dest.values():
                d["full_pct"], d["verdict_pct"] = pct(d["full"], d["n"]), pct(d["verdict"], d["n"])
    (outdir / "summary.json").write_text(json.dumps(s, indent=1))

    md = [f"# Security benchmark: {label}", "", f"Scored {s['scored_at']} - {len(rs)}/{len(tasks)} tasks, "
          f"{s['errors']} errors, {s['invalid_json']} invalid JSON, {s['time']['total_s'] / 60:.1f} min model time, "
          f"prompt version(s) {s['prompt_versions']}", "",
          f"**Overall full-credit: {s['overall_full_credit']}%**", "", "## Track A: code audit", "",
          "| verdict acc | precision | recall | false alarms on fixed twins | CWE acc | line acc | full credit |",
          "|---|---|---|---|---|---|---|",
          "| {verdict_acc}% | {precision}% | {recall}% | {false_alarm_rate}% | {cwe_acc}% | {line_acc}% | {full_credit}% |".format(**s["code"]),
          *variant_md(s),
          "", "## Track B: log forensics", "", "| attacker IP | technique | first seen | account | all four |", "|---|---|---|---|---|",
          "| {attacker_ip_acc}% | {technique_acc}% | {first_seen_acc}% | {account_acc}% | {full_acc}% |".format(**s["logs"]),
          "", "## Per task", "", "| task | key | answer | result | prompt tok | time s |", "|---|---|---|---|---|---|"]
    for t in tasks:
        r = results.get(t["id"])
        if not r or "error" in r:
            md.append(f"| {t['id']} | | {'ERROR' if r else 'not run'} | | | |")
            continue
        a = extract_json(r.get("raw")) or {}
        k = t["key"]
        if t["track"] == "code":
            ks = f"{k['label']} L{k['lines']}" if k["vulnerable"] else "safe"
            an = f"vuln={a.get('vulnerable')} {a.get('cwe')} L{a.get('line')}" if a else "invalid"
        else:
            ks = f"{k['attacker_ip']} {k['technique']} {k['first_seen']} {'/'.join(k['compromised_account'])}"
            an = f"{a.get('attacker_ip')} {a.get('technique')} {a.get('first_seen')} {a.get('compromised_account')}" if a else "invalid"
        sc = r["score"]
        res = "✅" if sc.get("full") else ("❌" if not sc.get("valid") else "◐ " + ",".join(x for x, v in sc.items() if v is False))
        md.append(f"| {t['id']} | {ks} | {an.replace('|', '/')} | {res} | {r.get('prompt_tokens')} | {r['wall_s']:.0f} |")
    if not logs:  # code-only run: drop the empty Track B table
        i = md.index("## Track B: log forensics")
        del md[i - 1:i + 5]
    (outdir / "summary.md").write_text("\n".join(md) + "\n")
    return s


VARIANT_HELP = {"obvious": "bug on the dangerous-API line", "hidden": "bug in data flow / bounds / helper",
                "decoy": "SAFE, dangerous API used correctly", "plain": "SAFE, boring code"}


def variant_md(s):
    if "by_variant" not in s:
        return []
    md = ["", "### By variant (generated suite)", "", "| variant | what it tests | full credit | correct verdict |", "|---|---|---|---|"]
    for v in ("obvious", "hidden", "decoy", "plain"):
        d = s["by_variant"].get(v)
        if d:
            md.append(f"| {v} | {VARIANT_HELP[v]} | {d['full']}/{d['n']} | {d['verdict']}/{d['n']} |")
    md += ["", "| family | full credit (all 4 variants) |", "|---|---|"]
    md += [f"| {f} | {d['full']}/{d['n']} |" for f, d in sorted(s["by_family"].items())]
    return md


def aggregate(label):
    base = ROOT / "results" / label
    runs = sorted(base.glob("gen-s*/summary.json"))
    if not runs:
        print("no generated-suite runs for", label)
        return
    ss = [json.loads(p.read_text()) for p in runs]

    def stat(vals):
        vals = [v for v in vals if v is not None]
        if not vals:
            return "-"
        mean = sum(vals) / len(vals)
        return f"{mean:.1f}% (range {min(vals):.0f}-{max(vals):.0f})"

    seeds = [p.parent.name for p in runs]
    md = [f"# Generated suite: {label}", "", f"Seeds: {', '.join(seeds)} ({len(ss)} runs x 32 tasks)", "",
          "| metric | mean over seeds |", "|---|---|",
          f"| full credit | {stat([x['code']['full_credit'] for x in ss])} |",
          f"| verdict accuracy | {stat([x['code']['verdict_acc'] for x in ss])} |",
          f"| recall (bugs flagged) | {stat([x['code']['recall'] for x in ss])} |",
          f"| false alarms on safe code | {stat([x['code']['false_alarm_rate'] for x in ss])} |",
          f"| CWE accuracy (vuln) | {stat([x['code']['cwe_acc'] for x in ss])} |",
          f"| line accuracy (vuln) | {stat([x['code']['line_acc'] for x in ss])} |", "",
          "| variant | full credit (mean) |", "|---|---|"]
    for v in ("obvious", "hidden", "decoy", "plain"):
        md.append(f"| {v} ({VARIANT_HELP[v]}) | {stat([x['by_variant'][v]['full_pct'] for x in ss if v in x.get('by_variant', {})])} |")
    md += ["", "| family | full credit (mean) |", "|---|---|"]
    fams = sorted({f for x in ss for f in x.get("by_family", {})})
    md += [f"| {f} | {stat([x['by_family'][f]['full_pct'] for x in ss if f in x.get('by_family', {})])} |" for f in fams]
    core = base / "summary.json"
    if core.exists():
        c = json.loads(core.read_text())["code"]
        md += ["", f"Hand-written textbook set for comparison: full credit {c['full_credit']}%, false alarms {c['false_alarm_rate']}%."]
    (base / "gen-aggregate.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--url", default="http://127.0.0.1:8081")
    ap.add_argument("--model", default="", help="model name (needed for Ollama)")
    ap.add_argument("--tracks", default="code,logs")
    ap.add_argument("--only", default="", help="comma-separated task ids")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--suite", choices=["core", "gen"], default="core",
                    help="core = hand-written code + logs; gen = procedurally generated code tasks")
    ap.add_argument("--seed", type=int, default=1, help="seed for --suite gen")
    ap.add_argument("--aggregate", action="store_true", help="summarize all gen-s* runs for this label")
    a = ap.parse_args()

    if a.aggregate:
        return aggregate(a.label)
    if a.suite == "gen":
        mpath = ROOT / "tasks" / "gen" / f"s{a.seed}" / "manifest.json"
        if not mpath.exists():
            import gen_code
            gen_code.build(a.seed)
    else:
        mpath = ROOT / "tasks" / "manifest.json"
    manifest = json.loads(mpath.read_text())
    tracks = set(a.tracks.split(","))
    tasks = [t for t in manifest["tasks"] if t["track"] in tracks and (not a.only or t["id"] in a.only.split(","))]
    outdir = ROOT / "results" / a.label / (f"gen-s{a.seed}" if a.suite == "gen" else "")
    outdir.mkdir(parents=True, exist_ok=True)
    rpath = outdir / "results.jsonl"
    results = load_results(rpath)

    if not a.score_only:
        todo = [t for t in tasks if t["id"] not in results or "error" in results[t["id"]]]
        print(f"[{a.label}] {len(todo)} of {len(tasks)} tasks to run -> {rpath}", flush=True)
        for i, t in enumerate(todo, 1):
            prompt, max_tok = build_prompt(t)
            rec = dict(id=t["id"], track=t["track"], prompt_version=PROMPT_VERSION, started=datetime.now().isoformat(timespec="seconds"))
            try:
                resp, wall = chat(a.url, a.model, prompt, max_tok, a.timeout)
                raw = resp["choices"][0]["message"].get("content", "")
                u = resp.get("usage", {})
                rec.update(raw=raw, wall_s=round(wall, 1), prompt_tokens=u.get("prompt_tokens"),
                           completion_tokens=u.get("completion_tokens"), timings=resp.get("timings"),
                           finish_reason=resp["choices"][0].get("finish_reason"))
                rec["score"] = score_task(t, extract_json(raw))
                status = "full" if rec["score"].get("full") else ("INVALID" if not rec["score"]["valid"] else "partial/wrong")
            except Exception as e:  # keep going; failed tasks are retried on the next run
                rec.update(error=repr(e), wall_s=0)
                status = "ERROR " + repr(e)[:80]
            with rpath.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            results[t["id"]] = rec
            print(f"  [{i}/{len(todo)}] {t['id']:<22} {rec.get('prompt_tokens') or '':>6} tok {rec['wall_s']:>6.0f}s  {status}", flush=True)

    s = summarize(tasks, results, a.label, outdir)
    print(f"\n{(outdir / 'summary.md')}\noverall full-credit {s['overall_full_credit']}%  "
          f"code {s['code']['full_credit']}% (false alarms {s['code']['false_alarm_rate']}%)"
          + (f"  logs {s['logs']['full_acc']}%" if s["logs"]["n"] else ""))


if __name__ == "__main__":
    sys.exit(main())
