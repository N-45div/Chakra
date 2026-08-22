"""Build the Chakra dashboard from run artifacts.

Reads whatever is in runs/ and emits a single self-contained HTML file. No
server, no CDN, no external assets: a demo that depends on a live process or a
network fetch is a demo that can fail in the room.

The page has two halves. The report half shows the loop mechanics, per-family
panels, Lane A utility, LOFO zero-shot results and the honesty ledger — every
number read from a JSON artifact written by a seeded run, with missing panels
saying so rather than rendering placeholders. The explorer half is the demo:
an in-browser replay of the recorded runs, labelled REPLAY on screen per
EXPERIMENT_CONTRACT §6, with a generation scrubber driving the attacker's
yield, the detector's recall and the parameter drift — defaults to the
across-seed aggregate because no seed may be selected for presentation.

The replay data is embedded as JSON from the same artifacts; the scrubber
animates client-side. Nothing is invented at render time.
"""

from __future__ import annotations

import html
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"
OUT = ROOT / "dashboard" / "index.html"

# Categorical slots 1-3 of the validated palette, both modes.
# Validated all-pairs: light worst CVD dE 9.2, normal-vision 24.0; dark 9.4/20.9.
PAL = {
    "pre": ("#2a78d6", "#3987e5"),   # recall before retraining
    "post": ("#eb6834", "#d95926"),  # recall after retraining
    "fpr": ("#1baf7a", "#199e70"),   # false positives on legit
}

FAMILY_NAMES = {
    "F11": "Enumeration / card testing",
    "F5": "UPI authorised push",
    "F6": "Mule networks",
    "F8": "Credit nurture & bust-out",
    "F10": "Agentic checkout manipulation",
}
FAMILY_RAIL = {"F11": "card", "F5": "UPI", "F6": "UPI", "F8": "card", "F10": "agentic"}


def load_runs():
    """Group run directories by family, newest directory per (family, seed)."""
    best: dict[tuple[str, str], tuple[float, dict]] = {}
    for d in sorted(RUNS.glob("*_seed*")):
        gen_f, score_f = d / "generations.json", d / "audit_score.json"
        if not gen_f.exists():
            continue
        fam = d.name.split("_seed")[0]
        seed = d.name.split("_seed")[1].split("_")[0]
        try:
            gens = json.loads(gen_f.read_text(encoding="utf-8"))
        except Exception:
            continue
        score = {}
        if score_f.exists():
            try:
                score = json.loads(score_f.read_text(encoding="utf-8"))
            except Exception:
                score = {}
        mtime = score_f.stat().st_mtime if score_f.exists() else 0.0
        rec = {"seed": seed, "gens": gens, "score": score, "dir": d.name}
        if (fam, seed) not in best or mtime > best[(fam, seed)][0]:
            best[(fam, seed)] = (mtime, rec)
    fams: dict[str, list[dict]] = {}
    for (fam, _seed), (_mt, rec) in best.items():
        fams.setdefault(fam, []).append(rec)
    for v in fams.values():
        v.sort(key=lambda r: r["seed"])
    return fams


def load_lane_a():
    f = RUNS / "lane_a_ulb.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_lofo():
    f = RUNS / "_lofo" / "lofo_results.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def med(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


# --------------------------------------------------------------------------
# charts — inline SVG, no libraries
# --------------------------------------------------------------------------

def line_chart(series, n_gen, height=210, width=560):
    """Multi-series line over generations. Thin 2px marks, recessive grid,
    direct end-labels so identity is never carried by colour alone."""
    if not n_gen:
        return "<p class='empty'>no generations recorded</p>"
    pad_l, pad_r, pad_t, pad_b = 46, 92, 16, 30
    iw, ih = width - pad_l - pad_r, height - pad_t - pad_b
    xs = lambda i: pad_l + (iw * (i / max(1, n_gen - 1)))  # noqa: E731
    ys = lambda v: pad_t + ih - (ih * max(0.0, min(1.0, v)))  # noqa: E731

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        y = ys(frac)
        parts.append(f'<line class="grid" x1="{pad_l}" y1="{y:.1f}" x2="{pad_l+iw}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis" x="{pad_l-8}" y="{y+3:.1f}" text-anchor="end">{frac:.2f}</text>')
    for i in range(n_gen):
        parts.append(
            f'<text class="axis" x="{xs(i):.1f}" y="{height-10}" text-anchor="middle">{i}</text>'
        )
    parts.append(
        f'<text class="axis-title" x="{pad_l+iw/2:.0f}" y="{height-0}" '
        f'text-anchor="middle">generation</text>'
    )

    for key, label, vals in series:
        pts = [(xs(i), ys(v)) for i, v in enumerate(vals) if v is not None]
        if not pts:
            continue
        d = " ".join(f"{'M' if k == 0 else 'L'}{x:.1f},{y:.1f}" for k, (x, y) in enumerate(pts))
        parts.append(f'<path class="ln ln-{key}" d="{d}"/>')
        for x, y in pts:
            parts.append(f'<circle class="pt pt-{key}" cx="{x:.1f}" cy="{y:.1f}" r="4"/>')
        ex, ey = pts[-1]
        parts.append(
            f'<text class="endlbl" x="{ex+9:.1f}" y="{ey+4:.1f}">{html.escape(label)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def bar_pair(rows, height=190, width=560):
    """Grouped horizontal bars with direct value labels (relief for the
    light-mode contrast warn)."""
    if not rows:
        return "<p class='empty'>no data</p>"
    pad_l, pad_r, pad_t = 206, 74, 12
    bar_h, gap = 20, 12
    ih = len(rows) * (bar_h + gap)
    height = pad_t + ih + 18
    iw = width - pad_l - pad_r
    top = max((r[1] for r in rows), default=1.0) or 1.0
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart">']
    for i, (label, val, key) in enumerate(rows):
        y = pad_t + i * (bar_h + gap)
        w = max(2.0, iw * (val / top))
        parts.append(
            f'<text class="barlbl" x="{pad_l-10}" y="{y+bar_h*0.72:.0f}" text-anchor="end">'
            f"{html.escape(label)}</text>"
        )
        parts.append(
            f'<rect class="bar bar-{key}" x="{pad_l}" y="{y}" width="{w:.1f}" '
            f'height="{bar_h}" rx="4"/>'
        )
        parts.append(
            f'<text class="barval" x="{pad_l+w+8:.1f}" y="{y+bar_h*0.72:.0f}">{val:.4f}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def table(headers, rows):
    h = "".join(f"<th>{html.escape(str(x))}</th>" for x in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows
    )
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


# --------------------------------------------------------------------------
# report panels
# --------------------------------------------------------------------------

def family_panel(fam, runs):
    name = FAMILY_NAMES.get(fam, fam)
    rail = FAMILY_RAIL.get(fam, "-")
    n_gen = max((len(r["gens"]) for r in runs), default=0)

    def per_gen(field):
        out = []
        for g in range(n_gen):
            vals = [r["gens"][g].get(field) for r in runs if g < len(r["gens"])]
            out.append(med(vals))
        return out

    pre, post = per_gen("recall_pre"), per_gen("recall_post")
    fpr = per_gen("fpr_post")
    evasion, yield_ = per_gen("episode_evasion"), per_gen("attacker_yield")
    prev = per_gen("prevalence")

    chart = line_chart(
        [
            ("pre", "recall (pre)", pre),
            ("post", "recall (post)", post),
            ("fpr", "FPR on legit", fpr),
        ],
        n_gen,
    )
    rows = [
        (
            g,
            f"{pre[g]:.3f}" if pre[g] is not None else "-",
            f"{post[g]:.3f}" if post[g] is not None else "-",
            f"{fpr[g]:.4f}" if fpr[g] is not None else "-",
            f"{evasion[g]:.3f}" if evasion[g] is not None else "-",
            f"₹{yield_[g]:,.0f}" if yield_[g] is not None else "-",
            f"{prev[g]:.4f}" if prev[g] is not None else "-",
        )
        for g in range(n_gen)
    ]
    tbl = table(
        ["gen", "recall pre", "recall post", "FPR legit", "episode evasion", "attacker yield", "prevalence"],
        rows,
    )

    lifts = [
        (post[g] - pre[g]) for g in range(n_gen) if pre[g] is not None and post[g] is not None
    ]
    improved = sum(1 for x in lifts if x > 0)
    seeds = ", ".join(r["seed"] for r in runs)

    audits = [r["score"].get("metrics", {}) for r in runs if r.get("score")]
    auprc = med([m.get("auprc") for m in audits]) if audits else None
    a_recall = med([m.get("recall_at_0_5pct_fpr") for m in audits]) if audits else None
    a_fpr = med([m.get("achieved_fpr_at_0_5pct_cut") for m in audits]) if audits else None
    vwr = med([m.get("value_weighted_recall") for m in audits]) if audits else None

    audit_line = (
        f"sealed audit — AUPRC {auprc:.4f} @ prevalence {med([m.get('prevalence') for m in audits]):.4%}, "
        f"recall {a_recall:.4f} at a frozen cut realising {a_fpr:.4%} FPR, "
        f"value-weighted recall {vwr:.3f}"
        if None not in (auprc, a_recall, a_fpr, vwr)
        else "sealed audit — not yet scored"
    )

    return f"""
    <section class="panel">
      <header class="panel-head">
        <div>
          <h3>{html.escape(fam)} · {html.escape(name)}</h3>
          <p class="sub">{rail} rail · {len(runs)} seeds ({html.escape(seeds)}) · median across seeds</p>
        </div>
        <div class="stat">
          <span class="stat-n">{improved}/{len(lifts)}</span>
          <span class="stat-l">generations where retraining raised recall</span>
        </div>
      </header>
      {chart}
      <p class="note">{html.escape(audit_line)}</p>
      <details><summary>Table view — every plotted value</summary>{tbl}</details>
    </section>"""


def lane_a_panel(la):
    if not la:
        return """<section class="panel"><h3>Lane A · synthetic-to-real</h3>
        <p class="empty">no Lane A artifact present.</p></section>"""
    rows = [
        ("TRTR — trained on REAL", la["trtr_auprc"], "pre"),
        ("TSTR — trained on SYNTHETIC", la["tstr_auprc"], "post"),
        ("random baseline (prevalence)", la["baseline_auprc"], "fpr"),
    ]
    tbl = table(
        ["measure", "TRTR (real)", "TSTR (synthetic)"],
        [
            ["AUPRC", f"{la['trtr_auprc']:.4f}", f"{la['tstr_auprc']:.4f}"],
            ["AUC", f"{la['trtr_auc']:.4f}", f"{la['tstr_auc']:.4f}"],
            [
                "recall @0.5% FPR",
                f"{la['trtr_recall_at_fpr']:.4f}",
                f"{la['tstr_recall_at_fpr']:.4f}",
            ],
            [
                "AUPRC with class weighting",
                f"{la['trtr_auprc_weighted']:.4f}",
                f"{la['tstr_auprc_weighted']:.4f}",
            ],
        ],
    )
    return f"""
    <section class="panel">
      <header class="panel-head">
        <div>
          <h3>Lane A · synthetic-to-real utility on real card data</h3>
          <p class="sub">{html.escape(la['dataset'])} · {la['n_dev']:,} dev / {la['n_test']:,} locked test ·
             test prevalence {la['prevalence_test']:.4%}</p>
        </div>
        <div class="stat stat-bad">
          <span class="stat-n">{la['utility_gap_auprc']:+.3f}</span>
          <span class="stat-l">AUPRC lost by training on synthetic</span>
        </div>
      </header>
      {bar_pair(rows)}
      <p class="note">
        Real-vs-synthetic discriminator AUC <strong>{la['discriminator_auc']:.3f}</strong> — a classifier
        separates our synthetic rows from real ones almost perfectly, so the Lane A generator has
        <strong>low fidelity</strong>. Reported because it is measured, not because it flatters.
        Class weighting costs <strong>{la['trtr_auprc'] - la['trtr_auprc_weighted']:+.3f}</strong> AUPRC
        on this real dataset while being near-neutral on our synthetic families — which is precisely
        why a synthetic-only pipeline can mislead.
      </p>
      <details><summary>Table view — every plotted value</summary>{tbl}</details>
    </section>"""


def lofo_panel(lofo):
    if not lofo:
        return """<section class="panel"><h3>Zero-shot (LOFO)</h3>
        <p class="empty">no LOFO artifact present (python scripts/run_lofo.py).</p></section>"""
    results = lofo.get("results", {})
    rows = []
    for fam, r in sorted(results.items()):
        if r.get("defined"):
            rows.append(
                (
                    fam,
                    "+".join(r.get("siblings", [])),
                    f"{r['auprc']:.4f}",
                    f"{r['recall_at_cut']:.4f} (FPR {r['achieved_fpr_at_cut']:.4%})",
                    f"{r['baseline_auprc']:.4f}",
                )
            )
        else:
            rows.append((fam, "none", "not defined — no within-rail sibling", "", ""))
    tbl = table(["held out", "trained on", "AUPRC", "recall @frozen cut", "logit baseline AUPRC"], rows)
    return f"""
    <section class="panel">
      <h3>Zero-shot (LOFO) — the detector frozen, the family unseen</h3>
      <p class="sub">Trained only on sibling families of the same rail; threshold frozen on
      sibling-only calibration; one evaluation on the held-out family. F10 has no agentic-rail
      sibling, so it receives no zero-shot number — absence of a number is the correct output.</p>
      {tbl}
    </section>"""


TAXONOMY_ROWS = [
    ("F11", "Enumeration / card testing", "card", "executable"),
    ("F5", "UPI authorised-push deception", "UPI", "executable"),
    ("F6", "Mule networks / layering", "UPI", "executable"),
    ("F8", "Credit nurture & bust-out", "card", "executable"),
    ("F10", "Agentic checkout manipulation", "agentic", "executable"),
    ("F1", "Real-time deepfake impersonation", "UPI/IMPS", "mapped"),
    ("F2", "Synthetic identity onboarding", "account", "mapped"),
    ("F3", "Voice-clone vishing", "telco→card/UPI", "mapped"),
    ("F4", "LLM phishing at industrial scale", "card/UPI", "mapped"),
    ("F7", "Fake-merchant acquiring abuse", "acquiring", "mapped"),
    ("F9", "Fabricated disputes / refund abuse", "card/UPI", "mapped"),
    ("F12", "AePS biometric fraud", "aeps", "mapped"),
    ("F13", "Personalised investment scams", "UPI/IMPS", "mapped"),
]


def taxonomy_panel():
    tbl = table(
        ["code", "family", "rail", "status"],
        TAXONOMY_ROWS,
    )
    return f"""
    <section class="panel">
      <h3>Identify — thirteen families mapped, five executable</h3>
      <p class="sub">Executable families enter the adaptive loop and receive quantitative
      evaluation. Mapped families are specified in docs/ATTACK_TAXONOMY.md with mechanism,
      GenAI delta and signal shape — they receive no performance claims, by design.</p>
      {tbl}
    </section>"""


LEDGER = [
    (
        "F-002",
        "retracted",
        "Attacker &ldquo;rediscovered the real-world evasion playbook&rdquo;",
        "Read from one seed. A second seed reproduced none of it, and with evasion at zero the "
        "fitness landscape was flat — the parameters were drifting at random.",
    ),
    (
        "F-003",
        "retracted",
        "&ldquo;Probe amount evolved upward on every seed&rdquo;",
        "The saved artifacts show the value identical from generation 0 to 5 on all five seeds. "
        "Those were the initial random draws; I compared them against the bound instead of "
        "against their own generation-0 values.",
    ),
    (
        "F-006",
        "retracted",
        "F5 produces a fitness gradient",
        "A controlled repeat — same config, same seeds, corrected utility — cut evasion from "
        "0.500/0.167 to 0.083/0.000. The gradient was a unit error that made evasion free, "
        "not a property of the family.",
    ),
    (
        "F-007",
        "fixed before it produced a result",
        "Attacker utility mixed units",
        "Cost in rupees was subtracted from a count of validated cards via an invented constant. "
        "Found by reading the code while tooling was unavailable, so no number was ever published "
        "from the broken model.",
    ),
]


def ledger_panel():
    items = "".join(
        f"""<li class="led led-{'retracted' if s == 'retracted' else 'caught'}">
          <div class="led-h"><code>{c}</code><span class="tag">{html.escape(s)}</span></div>
          <p class="led-claim">{t}</p>
          <p class="led-why">{w}</p>
        </li>"""
        for c, s, t, w in LEDGER
    )
    return f"""
    <section class="panel">
      <h3>Honesty ledger</h3>
      <p class="sub">Claims this system made, then withdrew, with the mechanism that caused each.
         Kept on the dashboard rather than buried in a repository file.</p>
      <ul class="ledger">{items}</ul>
    </section>"""


LOOP_SVG = """
<svg viewBox="0 0 760 210" role="img" class="loopdiag">
  <rect class="dg-a" x="8" y="70" width="150" height="58" rx="4"/>
  <text class="dg-t" x="24" y="94">Attack families</text>
  <text class="dg-s" x="24" y="112">parameterised</text>
  <rect class="dg-a" x="198" y="70" width="150" height="58" rx="4"/>
  <text class="dg-t" x="214" y="94">Generator</text>
  <text class="dg-s" x="214" y="112">raw events only</text>
  <rect class="dg-d" x="388" y="70" width="150" height="58" rx="4"/>
  <text class="dg-t" x="404" y="94">Detector</text>
  <text class="dg-s" x="404" y="112">network surface</text>
  <rect class="dg-n" x="578" y="42" width="170" height="50" rx="4"/>
  <text class="dg-t" x="594" y="63">Caught</text>
  <text class="dg-s" x="594" y="80">&#8594; training stream</text>
  <rect class="dg-n" x="578" y="112" width="170" height="50" rx="4"/>
  <text class="dg-t" x="594" y="133">Missed</text>
  <text class="dg-s" x="594" y="150">&#8594; attacker mutates</text>
  <path class="dg-l" d="M158 99 H192" marker-end="url(#ah)"/>
  <path class="dg-l" d="M348 99 H382" marker-end="url(#ah)"/>
  <path class="dg-l" d="M538 99 L558 99 L558 67 L572 67" marker-end="url(#ah)"/>
  <path class="dg-l" d="M538 99 L558 99 L558 137 L572 137" marker-end="url(#ah)"/>
  <path class="dg-f" d="M748 162 L748 190 L83 190 L83 134" marker-end="url(#ahr)"/>
  <text class="dg-fl" x="300" y="204">evasion &#8594; mutate &#8594; next generation</text>
  <defs>
    <marker id="ah" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
      <path d="M0 0 L7 3.5 L0 7 z" fill="currentColor"/></marker>
    <marker id="ahr" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
      <path d="M0 0 L7 3.5 L0 7 z" fill="#eb6834"/></marker>
  </defs>
</svg>"""


# --------------------------------------------------------------------------
# replay explorer (client-side, from embedded artifacts)
# --------------------------------------------------------------------------

def replay_data(fams):
    """Compact per-family JSON: seeds and their generation series."""
    payload = {}
    for fam, runs in fams.items():
        series = []
        for r in runs:
            gens = r["gens"]
            if not gens:
                continue
            series.append(
                {
                    "seed": r["seed"],
                    "gens": [
                        {
                            "recall_pre": g.get("recall_pre"),
                            "recall_post": g.get("recall_post"),
                            "fpr_post": g.get("fpr_post"),
                            "evasion": g.get("episode_evasion"),
                            "yield": g.get("attacker_yield"),
                            "prevalence": g.get("prevalence"),
                            "best_params": g.get("best_params") or {},
                        }
                        for g in gens
                    ],
                }
            )
        if series:
            payload[fam] = {
                "rail": FAMILY_RAIL.get(fam, "-"),
                "name": FAMILY_NAMES.get(fam, fam),
                "n_gen": len(series[0]["gens"]),
                "series": series,
                "audit": {
                    r["seed"]: r["score"].get("metrics", {})
                    for r in runs
                    if r.get("score", {}).get("metrics")
                },
            }
    return payload


REPLAY_JS = r"""
const R = JSON.parse(document.getElementById('replay-data').textContent);
const $ = (s) => document.querySelector(s);
let curFam = Object.keys(R)[0] || null;
let curSeed = 'agg';   // 'agg' = across-seed aggregate (default; no seed selected)
let curGen = 0, timer = null, playing = false;
const NS = 'http://www.w3.org/2000/svg';
const W = 560, H = 320, PL = 52, PR = 96, PT = 14, PB = 34;

function el(tag, attrs){const e=document.createElementNS(NS,tag);
  for(const k in attrs)e.setAttribute(k,attrs[k]);return e;}
function txt(x,y,s,cls,anchor){const t=el('text',{x,y,'class':cls});
  if(anchor)t.setAttribute('text-anchor',anchor);t.textContent=s;return t;}

function famTabs(){
  const box=$('#fam-tabs');box.textContent='';
  for(const f of Object.keys(R)){
    const b=document.createElement('button');
    b.className='ftab'+(f===curFam?' sel':'');
    b.textContent=f;b.onclick=()=>{curFam=f;curSeed='agg';curGen=0;seedSel();draw();};
    box.appendChild(b);
  }
}
function seedSel(){
  const s=$('#seed-sel');s.textContent='';
  const d=data();
  const opts=[['agg','all seeds (median \u00b1 IQR)']];
  for(const x of d.series)opts.push([x.seed,'seed '+x.seed]);
  for(const [v,l] of opts){const o=document.createElement('option');
    o.value=v;o.textContent=l;o.selected=(v===String(curSeed));s.appendChild(o);}
  s.onchange=()=>{curSeed=s.value==='agg'?'agg':s.value;curGen=0;draw();};
}
function data(){return R[curFam]||{series:[],n_gen:0};}
function series(){
  const d=data();
  if(curSeed==='agg'){
    const n=d.n_gen;const out=[];
    for(let g=0;g<n;g++){
      const v={recall_pre:[],recall_post:[],fpr_post:[],evasion:[],yield:[],prevalence:[]};
      for(const s of d.series)if(s.gens[g])for(const k in v){
        const x=s.gens[g][k];if(x!==null&&x!==undefined&&!isNaN(x))v[k].push(x);}
      const r={};
      for(const k in v){if(!v[k].length){r[k]=[null,null,null];continue;}
        v[k].sort((a,b)=>a-b);
        const q=p=>{const  i=(v[k].length-1)*p,lo=Math.floor(i),hi=Math.ceil(i);
          return lo===hi?v[k][lo]:v[k][lo]+(v[k][hi]-v[k][lo])*(i-lo);};
        r[k]=[q(.5),q(.25),q(.75)];}
      out.push(r);
    }
    return out;
  }
  const s=d.series.find(x=>x.seed===curSeed);
  return (s?s.gens:d.series[0].gens).map(g=>({
    recall_pre:[g.recall_pre,null,null],recall_post:[g.recall_post,null,null],
    fpr_post:[g.fpr_post,null,null],evasion:[g.evasion,null,null],
    yield:[g.yield,null,null],prevalence:[g.prevalence,null,null]}));
}
function yScale(vals,top){let vmax=Math.max(...vals.map(x=>x[0]).filter(x=>x!==null&&isFinite(x)),top);
  if(!isFinite(vmax))vmax=1;return v=>PT+(H-PT-PB)*(1-v/vmax);}

function draw(){
  const d=data();const ser=series();
  document.getElementById('rep-fam').textContent=
    curFam+' \u00b7 '+d.name+' \u00b7 '+d.rail+' rail \u00b7 '+
    (curSeed==='agg'?('all '+d.series.length+' seeds'):('seed '+curSeed));
  const n=Math.min(d.n_gen,ser.length);
  document.getElementById('gen-slider').max=Math.max(0,n-1);
  document.getElementById('gen-slider').value=curGen;
  document.getElementById('gen-label').textContent='generation '+curGen;

  const g=ser[curGen];const svg=$('#replay-chart');svg.textContent='';
  const grid=el('g',{});svg.appendChild(grid);
  const iw=W-PL-PR,ih=H-PT-PB;
  const xs=i=>PL+iw*(n>1?i/(n-1):0);

  // recall + fpr lines (all generations, current gen highlighted)
  const yr=yScale([...ser.map(s=>s.recall_pre),...ser.map(s=>s.recall_post),...ser.map(s=>s.fpr_post)],1);
  for(const frac of [0,.25,.5,.75,1]){const y=PT+ih*(1-frac);
    svg.appendChild(el('line',{'class':'grid',x1:PL,y1:y,x2:PL+iw,y2:y}));
    svg.appendChild(txt(PL-8,y+3,frac.toFixed(2),'axis','end'));}
  for(let i=0;i<n;i++)svg.appendChild(txt(xs(i),H-10,String(i),'axis','middle'));
  svg.appendChild(txt(PL+iw/2,H, 'generation','axis-title','middle'));

  const lines=[['ln-pre','recall pre','recall_pre'],['ln-post','recall post','recall_post'],
               ['ln-fpr','FPR legit','fpr_post']];
  for(const [cls,label,key] of lines){
    const pts=ser.map((s,i)=>[xs(i),yr(s[key][0])]).filter(p=>p[1]===p[1]);
    if(!pts.length)continue;
    const path=el('path',{d:pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1)).join(' '),'class':'ln '+cls});
    svg.appendChild(path);
    for(const [x,y] of pts)svg.appendChild(el('circle',{cx:x,cy:y,r:3,'class':'pt '+cls.slice(3)}));
    const e=pts[pts.length-1];svg.appendChild(txt(e[0]+8,e[1]+4,label,'endlbl'));
  }
  // current generation: yield + evasion as a right-side stat strip
  const stat=$('#rep-stats');stat.textContent='';
  const kv=[['episode evasion',g.evasion[0],x=>x.toFixed(3)],
            ['attacker yield \u20b9',g.yield[0],x=>Math.round(x).toLocaleString('en-IN')],
            ['prevalence',g.prevalence[0],x=>(x*100).toFixed(2)+'%'],
            ['monitor recall pre/post',
              g.recall_pre[0],x=>x.toFixed(3)+(g.recall_post[0]!==null?(' / '+g.recall_post[0].toFixed(3)):'')]];
  for(const [l,v,f] of kv){
    const row=document.createElement('div');row.className='rs';
    row.appendChild(Object.assign(document.createElement('span'),{className:'rs-l',textContent:l}));
    row.appendChild(Object.assign(document.createElement('span'),{className:'rs-v',
      textContent:v===null||v===undefined?'-':f(v)}));
    stat.appendChild(row);
  }
  drawParams(Math.floor(curGen));
}
function drawParams(g){
  const box=$('#rep-params');box.textContent='';
  const d=data();
  if(curSeed==='agg'){
    const firsts=d.series.map(s=>s.gens[g]&&s.gens[g].best_params).filter(Boolean);
    if(!firsts.length){box.appendChild(hint('no parameter records'));return;}
    box.appendChild(hint('median of seeds at generation '+g+' \u2014 parameters only mean anything when '
      +'the fitness gradient driving them is non-zero (F-002/F-003)'));
    const keys=Object.keys(firsts[0]);
    for(const k of keys){
      const vals=firsts.map(f=>f[k]).filter(v=>v!==null&&v!==undefined&&!isNaN(v));
      if(!vals.length)continue;
      const med=vals.sort((a,b)=>a-b)[Math.floor(vals.length/2)];
      chip(k,med);
    }
  } else {
    const s=d.series.find(x=>x.seed===curSeed);let bp=null;
    if(s&&s.gens[g])bp=s.gens[g].best_params;
    if(!bp||!Object.keys(bp).length){box.appendChild(hint('no parameter records'));return;}
    box.appendChild(hint('seed '+curSeed+' \u2014 parameters only mean anything when the fitness '
      +'gradient driving them is non-zero (F-002/F-003)'));
    for(const k of Object.keys(bp))chip(k,bp[k]);
  }
  function chip(k,v){
    const s=document.createElement('span');s.className='chip';
    s.textContent=k+'  '+(typeof v==='number'?v.toFixed(2):v);
    box.appendChild(s);
  }
  function hint(t){
    const s=document.createElement('span');s.className='hint';s.textContent=t;return s;
  }
}
function seek(d){curGen=Math.max(0,Math.min(d,data().n_gen-1));draw();}
function togglePlay(){
  playing=!playing;
  document.getElementById('play').textContent=playing?'\u23F8 pause':'\u25B8 play';
  if(playing){timer=setInterval(()=>{if(curGen>=data().n_gen-1){togglePlay();return;}seek(curGen+1);},900);}
  else clearInterval(timer);
}
window.addEventListener('DOMContentLoaded',()=>{if(!curFam)return;famTabs();seedSel();draw();});
"""


def replay_panel():
    return """
    <section class="panel" id="replay">
      <header class="panel-head">
        <div>
          <h3>The loop in action <span class="rep-tag">REPLAY</span></h3>
          <p class="sub" id="rep-fam"></p>
        </div>
        <div class="controls">
          <select id="seed-sel" aria-label="seed"></select>
          <button id="play" onclick="togglePlay()">&#9658; play</button>
          <input id="gen-slider" type="range" min="0" max="9" step="1" value="0"
                 oninput="seek(+this.value)" aria-label="generation"/>
          <span id="gen-label" class="gen-label">generation 0</span>
        </div>
      </header>
      <div class="rep-body">
        <svg id="replay-chart" viewBox="0 0 560 320" role="img" class="chart" preserveAspectRatio="none"></svg>
        <div id="rep-stats" class="rep-stats"></div>
      </div>
      <div id="rep-params" class="params"></div>
      <details><summary>What this shows, and what it does not show</summary>
        <p class="note">Play scrubs through the recorded generations. Blue is detector recall
        before retraining, orange after, green is the false-positive rate on legitimate traffic —
        the budget discipline holding while recall moves. Yield is what the attacker banked before
        the first alert. Recorded runs are shown as REPLAY per the experiment contract, and the
        default view is the across-seed aggregate because no single seed may be selected for
        presentation. Parameters are shown with their caveat: on a flat fitness landscape a
        parameter drift is noise, not strategy.</p>
      </details>
    </section>"""


# --------------------------------------------------------------------------

def build():
    fams = load_runs()
    la = load_lane_a()
    lofo = load_lofo()
    panels = "".join(family_panel(f, r) for f, r in sorted(fams.items()))
    if not panels:
        panels = "<section class='panel'><p class='empty'>No loop runs found in runs/.</p></section>"

    registered = all(
        len(runs) >= 20 and max((len(r["gens"]) for r in runs), default=0) >= 10
        for runs in fams.values()
    ) and len(fams) >= 5
    banner = (
        "<strong>Registered run complete.</strong> All five families finished the pre-registered "
        "20-seed, 10-generation protocol. Median and interquartile range across all seeds; no seed "
        "selected for presentation; no run discarded."
        if registered
        else "<strong>Development pilot, not a submission result.</strong> "
        "The registered experiment contract specifies 20 seeds and 10 generations; "
        "families below that are labelled pilot. No pilot figure is a competition claim."
    )

    css = """
:root{color-scheme:light;--bg:#f4f5f7;--surface:#fcfcfb;--ink:#101418;--ink2:#3d4550;
--muted:#6b7480;--line:#dfe3e8;--pre:#2a78d6;--post:#eb6834;--fpr:#1baf7a;
--bad:#d03b3b;--good:#0ca30c}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0e1013;
--surface:#1a1a19;--ink:#f2f4f6;--ink2:#c3c8d0;--muted:#8c95a1;--line:#2b3038;
--pre:#3080e6;--post:#d95926;--fpr:#199e70;--bad:#e06a6a;--good:#3cb85c}}
:root[data-theme="dark"]{--bg:#0e1013;--surface:#1a1a19;--ink:#f2f4f6;--ink2:#c3c8d0;
--muted:#8c95a1;--line:#2b3038;--pre:#3080e6;--post:#d95926;--fpr:#199e70;
--bad:#e06a6a;--good:#3cb85c}
*{box-sizing:border-box}
body{margin:0;padding:0 20px 72px;background:var(--bg);color:var(--ink);
font:16px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1000px;margin:0 auto}
header.top{padding:44px 0 22px;border-bottom:1px solid var(--line);margin-bottom:26px}
h1{margin:0;font-size:2rem;letter-spacing:-.01em}
h3{margin:0;font-size:1.08rem}
.lede{color:var(--ink2);max-width:64ch;margin:.6rem 0 0}
.banner{margin:18px 0 0;padding:12px 15px;border-left:3px solid var(--bad);
background:var(--surface);border-radius:0 4px 4px 0;font-size:.92rem;color:var(--ink2)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:6px;
padding:20px 22px;margin:0 0 18px}
.panel-head{display:flex;justify-content:space-between;gap:22px;align-items:flex-start;
margin-bottom:8px;flex-wrap:wrap}
.sub{color:var(--muted);font-size:.86rem;margin:.25rem 0 0}
.stat{text-align:right}
.stat-n{display:block;font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums}
.stat-bad .stat-n{color:var(--bad)}
.stat-l{display:block;font-size:.76rem;color:var(--muted);max-width:20ch}
.chart{width:100%;height:auto;display:block;margin:6px 0 4px;overflow:visible}
#replay-chart{background:var(--bg);border:1px solid var(--line);border-radius:4px;width:100%}
.grid{stroke:var(--line);stroke-width:1}
.axis{fill:var(--muted);font-size:10px}
.axis-title{fill:var(--muted);font-size:10px}
.ln{fill:none;stroke-width:2}
.ln-pre{stroke:var(--pre)}.ln-post{stroke:var(--post)}.ln-fpr{stroke:var(--fpr)}
.pt-pre{fill:var(--pre)}.pt-post{fill:var(--post)}.pt-fpr{fill:var(--fpr)}
.pt{stroke:var(--surface);stroke-width:2}
.endlbl{fill:var(--ink2);font-size:11px}
.bar-pre{fill:var(--pre)}.bar-post{fill:var(--post)}.bar-fpr{fill:var(--fpr)}
.barlbl{fill:var(--ink2);font-size:12px}
.barval{fill:var(--ink);font-size:12px;font-variant-numeric:tabular-nums}
.note{color:var(--ink2);font-size:.88rem;margin:.5rem 0 0}
.empty{color:var(--muted);font-style:italic}
details{margin-top:12px}
summary{cursor:pointer;color:var(--muted);font-size:.85rem}
table{border-collapse:collapse;width:100%;margin-top:10px;font-size:.82rem}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);
font-variant-numeric:tabular-nums}
th{color:var(--muted);font-weight:500}
.ledger{list-style:none;padding:0;margin:14px 0 0;display:grid;gap:12px}
.led{border-left:3px solid var(--bad);padding:10px 14px;background:var(--bg);border-radius:0 4px 4px 0}
.led-caught{border-left-color:var(--good)}
.led-h{display:flex;gap:10px;align-items:center}
.led-h code{font-size:.8rem;color:var(--muted)}
.tag{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.led-claim{margin:.4rem 0 .2rem;font-weight:600}
.led-why{margin:0;color:var(--ink2);font-size:.88rem}
.loopdiag{width:100%;height:auto;color:var(--muted)}
.dg-a{fill:none;stroke:var(--post)}.dg-d{fill:none;stroke:var(--pre)}
.dg-n{fill:none;stroke:var(--line)}
.dg-t{fill:var(--ink);font-size:13px;font-weight:600}
.dg-s{fill:var(--muted);font-size:10px}
.dg-l{stroke:var(--muted);fill:none;stroke-width:1.4}
.dg-f{stroke:var(--post);fill:none;stroke-width:1.6;stroke-dasharray:5 4}
.dg-fl{fill:var(--post);font-size:10px}
#fam-tabs{display:flex;gap:6px;margin:0 0 14px;flex-wrap:wrap}
.ftab{font:inherit;font-size:.85rem;padding:5px 14px;border:1px solid var(--line);
background:var(--surface);color:var(--ink2);border-radius:999px;cursor:pointer}
.ftab.sel{background:var(--pre);border-color:var(--pre);color:#fff;font-weight:600}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:.86rem}
.controls select{font:inherit;padding:4px 8px;border:1px solid var(--line);
background:var(--surface);color:var(--ink);border-radius:4px}
.controls button{font:inherit;padding:4px 12px;border:1px solid var(--line);
background:var(--surface);color:var(--ink);border-radius:4px;cursor:pointer}
.controls input[type=range]{width:150px}
.gen-label{color:var(--muted);font-variant-numeric:tabular-nums;min-width:96px}
.rep-tag{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:#fff;
background:var(--muted);padding:2px 8px;border-radius:3px;vertical-align:middle}
.rep-body{display:grid;grid-template-columns:minmax(0,1fr) 190px;gap:14px;align-items:start}
@media (max-width:720px){.rep-body{grid-template-columns:1fr}}
.rep-stats{display:grid;gap:8px}
.rs{display:flex;justify-content:space-between;gap:8px;background:var(--bg);
border:1px solid var(--line);border-radius:4px;padding:6px 10px;font-size:.82rem}
.rs-l{color:var(--muted)}
.rs-v{font-variant-numeric:tabular-nums;font-weight:600;text-align:right}
.params{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;align-items:center}
.chip{font-size:.78rem;font-variant-numeric:tabular-nums;border:1px solid var(--line);
background:var(--bg);padding:4px 10px;border-radius:999px;color:var(--ink2)}
.hint{font-size:.76rem;color:var(--muted);width:100%}
#rep-seed-note{color:var(--muted);font-size:.85rem;margin:.4rem 0 14px}
footer{color:var(--muted);font-size:.82rem;border-top:1px solid var(--line);
padding-top:18px;margin-top:26px}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

    rdata = json.dumps(replay_data(fams), default=float, ensure_ascii=False)
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chakra — adversarial fraud range</title>
<style>{css}</style></head>
<body><div class="wrap">
<header class="top">
  <h1>Chakra</h1>
  <p class="lede">A closed-loop adversarial fraud range for Indian payment rails. An attacker
  generates fraud, a detector scores it, the attacker mutates on what slipped through, and the
  detector retrains — with the improvement measured on batches neither of them trained on.</p>
  <div class="banner">{banner}</div>
</header>

<section class="panel">
  <h3>The loop</h3>
  <p class="sub">The red path is the part that makes this adversarial: the attacker consuming its
  own failures. Everything else is standard.</p>
  {LOOP_SVG}
</section>

{replay_panel()}

{taxonomy_panel()}

{panels}
{lofo_panel(lofo)}
{lane_a_panel(la)}
{ledger_panel()}

<footer>Every number is read from a seeded run artifact in <code>runs/</code>. Panels with no
artifact say so rather than showing a placeholder. Replay is labelled REPLAY per
docs/EXPERIMENT_CONTRACT.md §6.</footer>
</div>
<script type="application/json" id="replay-data">{html.escape(rdata)}</script>
<script>{REPLAY_JS}</script>
</body></html>"""

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8")
    return OUT, len(fams), la is not None, registered


if __name__ == "__main__":
    path, n_fams, has_la, registered = build()
    print(f"wrote {path}")
    print(f"  families: {n_fams}   lane A: {'yes' if has_la else 'no'}   "
          f"registered-complete: {'yes' if registered else 'no'}")