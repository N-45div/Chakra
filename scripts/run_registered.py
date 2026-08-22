"""The registered experiment, executed as pre-registered.

EXPERIMENT_CONTRACT §6 fixes the parameters before results exist: seeds
1000..1019, ten generations, every family in scope, median and interquartile
range across all twenty seeds, no seed selected for presentation and no run
discarded. This runner exists so that executing that protocol is one command
rather than forty copy-pasted invocations that could drift from the contract.

Runs are parallelised across (family, seed) pairs because each is fully
independent — its own world, its own detector, its own sealed audit. Nothing
is shared between them, so parallelism changes nothing about what any single
run computes; it only changes when it finishes.

A run whose output directory already exists AND contains a committed audit
score is skipped, so an interrupted batch resumes instead of recomputing.
The directory name embeds the code version hash, so any change to chakra/
invalidates previous directories automatically rather than silently reusing
them — the same guard run_experiment.py applies within a single run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FAMILIES = ["F5", "F6", "F8", "F10", "F11"]
SEEDS = list(range(1000, 1020))
GENERATIONS = 10


def _run_done(out_dir: Path) -> bool:
    """Complete means a REGISTERED run: audit scored AND committed, with the
    full ten-generation series.

    Plain 'has an audit_score.json' was not enough — it skipped registered jobs
    whose (family, seed) had any older artifact at all: 2-generation smoke runs
    and 6-generation development pilots counted as complete and four registered
    jobs were silently never executed. A run is only a stand-in for this batch
    when its generations.json is the registered length.
    """
    score = out_dir / "audit_score.json"
    gens = out_dir / "generations.json"
    if not score.exists() or not gens.exists():
        return False
    try:
        meta = json.loads(score.read_text(encoding="utf-8"))
        series = json.loads(gens.read_text(encoding="utf-8"))
        return bool(meta.get("metrics")) and len(series) >= GENERATIONS
    except Exception:
        return False


def _one(job: tuple[str, int]) -> dict:
    family, seed = job
    t0 = time.time()
    from scripts.run_experiment import run_one

    try:
        results, bundle, _audit = run_one(family, seed, GENERATIONS, small=False)
        # locate the directory this run wrote: keyed on family/seed/version/config
        return {
            "family": family,
            "seed": seed,
            "ok": True,
            "seconds": round(time.time() - t0, 1),
            "auprc": float(bundle.auprc),
            "recall_at_cut": float(bundle.recall_at_0_5pct_fpr),
            "achieved_fpr": float(bundle.achieved_fpr_at_0_5pct_cut),
            "value_weighted_recall": float(bundle.value_weighted_recall),
            "prevalence": float(bundle.prevalence),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "family": family,
            "seed": seed,
            "ok": False,
            "seconds": round(time.time() - t0, 1),
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc(limit=4),
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--families", nargs="*", default=FAMILIES)
    ap.add_argument("--seeds", type=int, nargs="*", default=SEEDS)
    args = ap.parse_args()

    jobs = [(f, s) for f in args.families for s in args.seeds]
    runs_dir = ROOT / "runs"
    pending = []
    for f, s in jobs:
        already = [
            d
            for d in runs_dir.glob(f"{f}_seed{s}_*")
            if d.is_dir() and _run_done(d)
        ]
        if already:
            print(f"skip {f} seed {s}: complete run exists at {already[0].name}")
            continue
        pending.append((f, s))
    print(f"registered batch: {len(pending)} of {len(jobs)} runs to execute")
    print(f"generations: {GENERATIONS} | workers: {args.workers}\n")

    done = 0
    failures = []
    t0 = time.time()
    if pending:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(_one, j): j for j in pending}
            for fut in as_completed(futures):
                fam, seed = futures[fut]
                res = fut.result()
                done += 1
                if res["ok"]:
                    print(
                        f"[{done:>3}/{len(pending)}] {fam} seed {seed}  "
                        f"AUPRC {res['auprc']:.3f}  rec@cut {res['recall_at_cut']:.3f} "
                        f"(FPR {res['achieved_fpr']:.4%})  {res['seconds']:.0f}s"
                    )
                else:
                    failures.append(res)
                    print(f"[{done:>3}/{len(pending)}] {fam} seed {seed}  FAILED: {res['error']}")
                    sys.stdout.flush()

    wall = time.time() - t0
    print(f"\nbatch complete in {wall/60:.1f} min — {len(jobs) - len(failures)} ok, "
          f"{len(failures)} failed")

    if failures:
        out = ROOT / "runs" / "_registered_failures.json"
        out.write_text(json.dumps(failures, indent=2), encoding="utf-8")
        print(f"failure details written to {out.name}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
