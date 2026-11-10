#!/usr/bin/env python3
"""Procedural code-audit tasks: fresh, never-published samples for every seed.

8 bug families x 4 variants:
  obvious  - the bug sits on the line with the "dangerous" API (textbook shape)
  hidden   - same bug class, but the flaw is in data flow / a helper / a bounds check
  decoy    - SAFE, but uses the scary-looking API correctly (shell=True + shlex.quote, ...)
  plain    - SAFE, written the boring way
Pattern-matching on APIs scores well on `obvious` and badly on `hidden` + `decoy`.

Domain, identifiers, tool paths and filler helpers are drawn from the seed, so each
seed produces different source text. @@VULN@@ marks key lines and is stripped.

  python3 gen_code.py --seed 7          # writes tasks/gen/s7/
"""
import argparse
import ast
import json
import random
import re
import shutil
import subprocess
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent
MARK = re.compile(r"[ \t]*(?:/\*\s*@@VULN@@\s*\*/|//\s*@@VULN@@|#\s*@@VULN@@)")

DOMAINS = [
    ("specimen", "specimens", "herbarium"), ("booking", "bookings", "observatory"), ("recipe", "recipes", "brewhouse"),
    ("manifest", "manifests", "dronefleet"), ("sample", "samples", "soillab"), ("ticket", "tickets", "ferryline"),
    ("pattern", "patterns", "loomworks"), ("score", "scores", "choirhub"), ("route", "routes", "glidernet"),
    ("batch", "batches", "kilnlog"), ("parcel", "parcels", "cargobike"), ("survey", "surveys", "tidegauge"),
    ("fixture", "fixtures", "leaguedesk"), ("lesson", "lessons", "dojoplan"), ("hive", "hives", "apiary"),
    ("print", "prints", "darkroom"), ("seedlot", "seedlots", "seedbank"), ("track", "tracks", "railyard"),
]
VERBS = ["fetch", "load", "render", "export", "resolve", "collect", "prepare", "emit", "apply", "process", "sync", "stage"]
TOOLS = ["pdfstitch", "rasterize", "zonepack", "tilebake", "labelgen", "sheetfold", "manifestc", "gridcut"]

PY_FILLERS = [
    "def ${f}(value, default=0):\n    try:\n        return int(value)\n    except (TypeError, ValueError):\n        return default\n",
    "def ${f}(items, size):\n    for i in range(0, len(items), size):\n        yield items[i:i + size]\n",
    "def ${f}(text):\n    return \" \".join(str(text).split()).strip().lower()\n",
    "def ${f}(seconds):\n    minutes, seconds = divmod(int(seconds), 60)\n    hours, minutes = divmod(minutes, 60)\n    return f\"{hours:02d}:{minutes:02d}:{seconds:02d}\"\n",
    "def ${f}(mapping, *keys):\n    return {k: mapping[k] for k in keys if k in mapping}\n",
]
C_FILLERS = [
    "static unsigned ${f}(const char *s)\n{\n    unsigned h = 5381;\n    while (*s != '\\0')\n        h = h * 33u + (unsigned char)*s++;\n    return h;\n}\n",
    "static void ${f}(char *s)\n{\n    size_t n = strlen(s);\n    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\\n'))\n        s[--n] = '\\0';\n}\n",
    "static int ${f}(int v, int lo, int hi)\n{\n    return v < lo ? lo : (v > hi ? hi : v);\n}\n",
    "static int ${f}(const char *a, const char *b)\n{\n    return a != NULL && b != NULL && strcmp(a, b) == 0;\n}\n",
]
JS_FILLERS = [
    "function ${f}(value, fallback) {\n  const n = Number.parseInt(value, 10);\n  return Number.isNaN(n) ? fallback : n;\n}\n",
    "function ${f}(date) {\n  return new Date(date).toISOString().slice(0, 10);\n}\n",
    "function ${f}(rows, key) {\n  return rows.reduce((acc, r) => ((acc[r[key]] = r), acc), {});\n}\n",
]

# ------------------------------------------------------------------ families --
# Each family: lang, ext, accepted CWEs, skeleton, and a body per variant.
# ${...} placeholders are filled from the per-task context.

F = {}

F["cmd_injection"] = dict(lang="Python", ext=".py", cwe=[78, 77, 88], skel='''import os
import shlex
import subprocess

from flask import Flask, abort, request, send_file

app = Flask(__name__)
WORK_DIR = "/srv/${app}/work"
TOOL = "/opt/${app}/bin/${tool}"

${FILLER1}
${HELPERS}
@app.route("/${ents}/<int:item_id>/export", methods=["POST"])
def ${fn_main}(item_id):
    label = request.form.get("label", "export")
    out_path = os.path.join(WORK_DIR, f"${ent}-{item_id}.out")
${BODY}
    if rc != 0:
        abort(500)
    return send_file(out_path)

${FILLER2}''', variants=dict(
    obvious=dict(helpers="", body='''    rc = subprocess.call(f"{TOOL} --id {item_id} --label {label} --out {out_path}", shell=True)  # @@VULN@@'''),
    hidden=dict(helpers='''def ${fn_build}(item_id, label, out_path):
    parts = [TOOL, "--id", str(item_id), "--label", label, "--out", out_path]
    return " ".join(parts)  # @@VULN@@


def ${fn_run}(cmdline):
    proc = subprocess.run(cmdline, shell=True, capture_output=True, timeout=120)  # @@VULN@@
    return proc.returncode

''', body='''    rc = ${fn_run}(${fn_build}(item_id, label, out_path))'''),
    decoy=dict(helpers="", body='''    argv = [TOOL, "--id", str(item_id), "--label", label, "--out", out_path]
    rc = subprocess.call(" ".join(shlex.quote(a) for a in argv), shell=True)'''),
    plain=dict(helpers="", body='''    rc = subprocess.call([TOOL, "--id", str(item_id), "--label", label, "--out", out_path])'''),
))

F["sql_injection"] = dict(lang="Python", ext=".py", cwe=[89, 943], skel='''import sqlite3

SORT_COLUMNS = {"name": "name", "date": "created_at", "size": "${numcol}"}

${FILLER1}

class ${Ent}Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row

    def get(self, item_id):
        return self.db.execute("SELECT * FROM ${ents} WHERE id = ?", (item_id,)).fetchone()

    def search(self, owner, sort="name"):
${BODY}

${FILLER2}

def ${fn_main}(query, store):
    """Web handler: `query` holds the raw query-string parameters from the client."""
    rows = store.search(query.get("owner", ""), query.get("sort", "name"))
    return [dict(r) for r in rows]
''', variants=dict(
    obvious=dict(body='''        sql = f"SELECT id, name, created_at FROM ${ents} WHERE owner = '{owner}' ORDER BY name"  # @@VULN@@
        return self.db.execute(sql).fetchall()'''),
    hidden=dict(body='''        column = SORT_COLUMNS.get(sort, sort)  # @@VULN@@
        sql = f"SELECT id, name, created_at FROM ${ents} WHERE owner = ? ORDER BY {column}"  # @@VULN@@
        return self.db.execute(sql, (owner,)).fetchall()'''),
    decoy=dict(body='''        if sort not in SORT_COLUMNS:
            raise ValueError("unsupported sort key")
        column = SORT_COLUMNS[sort]
        sql = f"SELECT id, name, created_at FROM ${ents} WHERE owner = ? ORDER BY {column}"
        return self.db.execute(sql, (owner,)).fetchall()'''),
    plain=dict(body='''        return self.db.execute(
            "SELECT id, name, created_at FROM ${ents} WHERE owner = ? ORDER BY name", (owner,)
        ).fetchall()'''),
))

F["path_traversal"] = dict(lang="Python", ext=".py", cwe=[22, 23, 36, 73], skel='''import os

BASE_DIR = "/var/lib/${app}/${ents}"
INDEX = {"cover": "cover.png", "sheet": "sheet.pdf", "notes": "notes.txt"}

${FILLER1}

def ${fn_main}(query):
    """Serves a ${ent} attachment. `query` is the parsed URL query string from the client."""
    name = query.get("file", "")
${BODY}
    try:
        with open(path, "rb") as fh:
            return 200, fh.read()
    except (FileNotFoundError, IsADirectoryError):
        return 404, b"not found"

${FILLER2}''', variants=dict(
    obvious=dict(body='''    path = os.path.join(BASE_DIR, name)  # @@VULN@@'''),
    hidden=dict(body='''    name = name.replace("../", "")  # @@VULN@@
    path = os.path.join(BASE_DIR, name.lstrip("/"))  # @@VULN@@'''),
    decoy=dict(body='''    path = os.path.realpath(os.path.join(BASE_DIR, name))
    if os.path.commonpath([path, BASE_DIR]) != BASE_DIR:
        return 403, b"forbidden"'''),
    plain=dict(body='''    entry = INDEX.get(name)
    if entry is None:
        return 404, b"not found"
    path = os.path.join(BASE_DIR, entry)'''),
))

F["deserialization"] = dict(lang="Python", ext=".py", cwe=[502, 345, 347, 354, 565], skel='''import base64
import hashlib
import hmac
import json
import os
import pickle

SECRET = os.environ["${APP}_SECRET"].encode()
_restore = pickle.loads

${FILLER1}

def ${fn_load}(cookie_value):
    """Restores the client's saved ${ent} draft from the cookie the browser sent."""
    if not cookie_value:
        return {}
${BODY}


def ${fn_save}(draft):
${SAVE}

${FILLER2}''', variants=dict(
    obvious=dict(body='''    return pickle.loads(base64.urlsafe_b64decode(cookie_value))  # @@VULN@@''',
                 save='''    return base64.urlsafe_b64encode(pickle.dumps(draft)).decode()'''),
    hidden=dict(body='''    blob = base64.urlsafe_b64decode(cookie_value)
    body, _, digest = blob.rpartition(b".")
    if digest != hashlib.sha256(body).hexdigest().encode():  # @@VULN@@
        return {}
    return _restore(body)  # @@VULN@@''',
                save='''    body = pickle.dumps(draft)
    return base64.urlsafe_b64encode(body + b"." + hashlib.sha256(body).hexdigest().encode()).decode()'''),
    decoy=dict(body='''    blob = base64.urlsafe_b64decode(cookie_value)
    body, _, sig = blob.rpartition(b".")
    expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(sig, expected):
        return {}
    return pickle.loads(body)''',
               save='''    body = pickle.dumps(draft)
    sig = hmac.new(SECRET, body, hashlib.sha256).hexdigest().encode()
    return base64.urlsafe_b64encode(body + b"." + sig).decode()'''),
    plain=dict(body='''    try:
        return json.loads(base64.urlsafe_b64decode(cookie_value))
    except ValueError:
        return {}''',
               save='''    return base64.urlsafe_b64encode(json.dumps(draft).encode()).decode()'''),
))

F["buffer_copy"] = dict(lang="C", ext=".c", cwe=[119, 120, 121, 122, 787, 193, 170], skel='''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ${NAMEMAX} ${namelen}

struct ${ent}_rec {
    char name[${NAMEMAX}];
    long value;
};

${FILLER1}

/* Parses one "name=value" line received from the network peer. */
static int ${fn_parse}(const char *line, struct ${ent}_rec *out)
{
    const char *eq = strchr(line, '=');
    if (eq == NULL)
        return -1;
    size_t len = (size_t)(eq - line);
${BODY}
    out->value = strtol(eq + 1, NULL, 10);
    return 0;
}

${FILLER2}

int main(void)
{
    char line[1024];
    struct ${ent}_rec rec;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\\r\\n")] = '\\0';
        if (${fn_parse}(line, &rec) == 0)
            printf("%s -> %ld\\n", rec.name, rec.value);
    }
    return 0;
}
''', variants=dict(
    obvious=dict(body='''    char tmp[1024];
    memcpy(tmp, line, len);
    tmp[len] = '\\0';
    strcpy(out->name, tmp); /* @@VULN@@ */'''),
    hidden=dict(body='''    if (len > sizeof(out->name)) /* @@VULN@@ */
        return -1;
    memcpy(out->name, line, len);
    out->name[len] = '\\0'; /* @@VULN@@ */'''),
    decoy=dict(body='''    char tmp[1024];
    memcpy(tmp, line, len);
    tmp[len] = '\\0';
    if (strlen(tmp) >= sizeof(out->name))
        return -1;
    strcpy(out->name, tmp);'''),
    plain=dict(body='''    if (len >= sizeof(out->name))
        return -1;
    memcpy(out->name, line, len);
    out->name[len] = '\\0';'''),
))

F["int_overflow"] = dict(lang="C", ext=".c", cwe=[190, 680, 131, 122, 787, 197], skel='''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ${ent}_row {
    uint32_t id;
    uint32_t flags;
    double   reading;
};

struct ${ent}_table {
    uint32_t count;
    struct ${ent}_row *rows;
};

${FILLER1}

/* Loads a table from a file uploaded by the user. Format: row count, then rows. */
struct ${ent}_table *${fn_load}(FILE *f)
{
    struct ${ent}_table *t = malloc(sizeof(*t));
    if (t == NULL)
        return NULL;
${BODY}
    if (t->rows == NULL) {
        free(t);
        return NULL;
    }
    for (uint32_t i = 0; i < t->count; i++) {
        if (fread(&t->rows[i], sizeof(struct ${ent}_row), 1, f) != 1) {
            free(t->rows);
            free(t);
            return NULL;
        }
    }
    return t;
}

${FILLER2}''', variants=dict(
    obvious=dict(body='''    if (fread(&t->count, sizeof(uint32_t), 1, f) != 1) {
        free(t);
        return NULL;
    }
    uint32_t bytes = t->count * (uint32_t)sizeof(struct ${ent}_row); /* @@VULN@@ */
    t->rows = malloc(bytes);'''),
    hidden=dict(body='''    uint16_t count16;
    if (fread(&count16, sizeof(uint16_t), 1, f) != 1) {
        free(t);
        return NULL;
    }
    t->count = count16;
    uint16_t slots = count16 + ${slack}; /* @@VULN@@ */
    t->rows = malloc((size_t)slots * sizeof(struct ${ent}_row)); /* @@VULN@@ */'''),
    decoy=dict(body='''    if (fread(&t->count, sizeof(uint32_t), 1, f) != 1) {
        free(t);
        return NULL;
    }
    if (t->count > SIZE_MAX / sizeof(struct ${ent}_row)) {
        free(t);
        return NULL;
    }
    t->rows = malloc((size_t)t->count * sizeof(struct ${ent}_row));'''),
    plain=dict(body='''    if (fread(&t->count, sizeof(uint32_t), 1, f) != 1 || t->count > ${maxrows}) {
        free(t);
        return NULL;
    }
    t->rows = calloc(t->count, sizeof(struct ${ent}_row));'''),
))

F["use_after_free"] = dict(lang="C", ext=".c", cwe=[416, 825], skel='''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ${ent}_job {
    int   id;
    int   refs;
    char *payload;
    struct ${ent}_job *next;
};

static struct ${ent}_job *queue_head;

${FILLER1}

static void ${fn_release}(struct ${ent}_job *j)
{
    free(j->payload);
    free(j);
}

/* Drops one reference; the job is destroyed when the last reference goes away. */
static void ${fn_put}(struct ${ent}_job *j)
{
    if (--j->refs == 0)
        ${fn_release}(j);
}

/* Called by a worker when it is done with a job it holds a reference to.
 * The worker's reference is usually the last one. */
static void ${fn_finish}(struct ${ent}_job *j, int status)
{
${BODY}
}

/* Frees every queued job at shutdown. */
static void ${fn_drain}(void)
{
    struct ${ent}_job *next;
    for (struct ${ent}_job *j = queue_head; j != NULL; j = next) {
        next = j->next;
        ${fn_release}(j);
    }
    queue_head = NULL;
}

${FILLER2}''', variants=dict(
    obvious=dict(body='''    ${fn_release}(j);
    printf("${ent} job %d finished with status %d\\n", j->id, status); /* @@VULN@@ */'''),
    hidden=dict(body='''    ${fn_put}(j); /* @@VULN@@ */
    printf("${ent} job %d finished with status %d\\n", j->id, status); /* @@VULN@@ */'''),
    decoy=dict(body='''    int id = j->id;
    ${fn_put}(j);
    printf("${ent} job %d finished with status %d\\n", id, status);'''),
    plain=dict(body='''    printf("${ent} job %d finished with status %d\\n", j->id, status);
    ${fn_put}(j);'''),
))

F["idor"] = dict(lang="JavaScript (Node.js/Express)", ext=".js", cwe=[639, 862, 863, 284, 285, 566], skel='''const express = require("express");
const { requireLogin } = require("./auth");
const db = require("./db");

const router = express.Router();

${FILLER1}
router.get("/${ents}", requireLogin, async (req, res) => {
  const rows = await db.query("SELECT id, title FROM ${ents} WHERE owner_id = $1", [req.user.id]);
  res.json(rows);
});

router.get("/${ents}/:id", requireLogin, async (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "bad id" });
${BODY}
  res.json(doc);
});

${FILLER2}
module.exports = router;
''', variants=dict(
    obvious=dict(body='''  const rows = await db.query("SELECT * FROM ${ents} WHERE id = $1", [id]); // @@VULN@@
  const doc = rows[0];
  if (!doc) return res.status(404).json({ error: "not found" });'''),
    hidden=dict(body='''  const rows = await db.query("SELECT * FROM ${ents} WHERE id = $1", [id]);
  const doc = rows[0];
  if (!doc) return res.status(404).json({ error: "not found" });
  if (doc.owner_id !== req.user.id && !req.query.share_token) { // @@VULN@@
    return res.status(404).json({ error: "not found" });
  }'''),
    decoy=dict(body='''  const rows = await db.query("SELECT * FROM ${ents} WHERE id = $1", [id]);
  const doc = rows[0];
  if (!doc) return res.status(404).json({ error: "not found" });
  const shared = typeof doc.share_token === "string" && doc.share_token.length >= 32 &&
    req.query.share_token === doc.share_token;
  if (doc.owner_id !== req.user.id && !shared) {
    return res.status(404).json({ error: "not found" });
  }'''),
    plain=dict(body='''  const rows = await db.query("SELECT * FROM ${ents} WHERE id = $1 AND owner_id = $2", [id, req.user.id]);
  const doc = rows[0];
  if (!doc) return res.status(404).json({ error: "not found" });'''),
))

VARIANTS = ["obvious", "hidden", "decoy", "plain"]


def strip_markers(text):
    out, marked = [], []
    for i, line in enumerate(text.split("\n"), 1):
        if "@@VULN@@" in line:
            marked.append(i)
            line = MARK.sub("", line)
        out.append(line)
    return "\n".join(out), marked


def fill(text, ctx):
    return Template(text).safe_substitute(ctx)


def make_ctx(rng):
    ent, ents, app = rng.choice(DOMAINS)
    names = rng.sample(VERBS, 6)
    ctx = dict(ent=ent, ents=ents, app=app, APP=app.upper(), Ent=ent.capitalize(), tool=rng.choice(TOOLS),
               numcol=rng.choice(["weight_g", "page_count", "duration_s", "volume_ml"]),
               NAMEMAX=rng.choice(["NAME_MAX_LEN", "LABEL_LEN", "KEY_LEN"]), namelen=rng.choice([24, 32, 48, 64]),
               slack=rng.choice([4, 8, 16]), maxrows=rng.choice([10000, 65536, 100000]))
    for k, v in zip(["fn_main", "fn_build", "fn_run", "fn_load", "fn_save", "fn_parse"], names):
        ctx[k] = f"{v}_{ent}"
    ctx["fn_build"] = f"build_{ent}_cmd"
    ctx["fn_release"], ctx["fn_put"], ctx["fn_finish"], ctx["fn_drain"] = (
        f"{ent}_destroy", f"{ent}_unref", f"{ent}_complete", f"{ent}_drain_all")
    return ctx


def fillers(rng, ext, ctx):
    pool = {".py": PY_FILLERS, ".c": C_FILLERS, ".js": JS_FILLERS}[ext]
    picks = rng.sample(pool, 2)
    out, used = [], set()
    for p in picks:
        if rng.random() < 0.3:
            out.append("")
            continue
        name = None
        while name is None or name in used:
            name = f"{rng.choice(['norm', 'clamp', 'chunk', 'fmt', 'pick', 'hash', 'trim'])}_{rng.choice(['val', 'args', 'span', 'text', 'key'])}"
        used.add(name)
        if ext == ".py" and rng.random() < 0.5:
            name = "_" + name
        out.append(fill(p, dict(f=name)))
    return out


def render(fam, variant, rng):
    spec = F[fam]
    v = spec["variants"][variant]
    ctx = make_ctx(rng)
    f1, f2 = fillers(rng, spec["ext"], ctx)
    ctx.update(FILLER1=f1, FILLER2=f2, BODY=fill(v["body"], ctx), HELPERS=fill(v.get("helpers", ""), ctx),
               SAVE=fill(v.get("save", ""), ctx))
    text = fill(spec["skel"], ctx)
    text = re.sub(r"\n{4,}", "\n\n\n", text).strip() + "\n"
    leftover = re.findall(r"\$\{\w+\}|\$[A-Za-z_]\w*", text)
    assert not leftover, (fam, variant, leftover)
    return text


def check_syntax(path, lang):
    if path.suffix == ".py":
        ast.parse(path.read_text())
    elif path.suffix == ".c" and shutil.which("gcc"):
        r = subprocess.run(["gcc", "-fsyntax-only", "-Wall", "-Wno-unused-function", "-Wno-unused-variable", str(path)],
                           capture_output=True, text=True)
        assert r.returncode == 0 and "warning" not in r.stderr, f"{path}: {r.stderr}"
    elif path.suffix == ".js" and shutil.which("node"):
        r = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        assert r.returncode == 0, f"{path}: {r.stderr}"


def build(seed):
    rng = random.Random(f"gen-{seed}")
    out = ROOT / "tasks" / "gen" / f"s{seed}"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tasks = []
    for fam in F:
        for variant in VARIANTS:
            raw = render(fam, variant, rng)
            text, lines = strip_markers(raw)
            vulnerable = variant in ("obvious", "hidden")
            assert bool(lines) == vulnerable, (fam, variant, lines)
            tid = f"gen{seed}-{fam}-{variant}"
            path = out / f"{tid}{F[fam]['ext']}"
            path.write_text(text)
            check_syntax(path, F[fam]["lang"])
            tasks.append(dict(id=tid, track="code", file=str(path.relative_to(ROOT)), lang=F[fam]["lang"],
                              key=dict(vulnerable=vulnerable, cwe=F[fam]["cwe"] if vulnerable else [], lines=lines,
                                       label=f"{fam} ({variant})", family=fam, variant=variant)))
    rng.shuffle(tasks)
    (out / "manifest.json").write_text(json.dumps(dict(seed=seed, suite="gen", tasks=tasks), indent=1))
    return out / "manifest.json"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, nargs="+", default=[1])
    for s in ap.parse_args().seed:
        m = build(s)
        print(f"seed {s}: {len(json.loads(m.read_text())['tasks'])} tasks -> {m}")
