"""Multi-seed experiment runner.

Per the experiment contract: pre-registered seeds, median and interquartile
range across all of them, no seed selected for presentation and no run
discarded. A single seed is an anecdote — an earlier write-up read one seed's
evolved parameters as "the attacker rediscovered the real-world evasion
playbook", and a second seed did not reproduce half of it.

Writes per-run artifacts and a sealed, hash-verified audit score into runs/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

import numpy as np

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.rng import Rng
from chakra.loop.orchestrator import Loop, LoopConfig

RUNS = Path(__file__).resolve().parents[1] / "runs"


def _code_version() -> str:
    """Git commit plus a hash of the source that produces results.

    Run directories keyed only on family and seed silently overwrote each other
    across code changes: one run's score file ended up beside another run's
    audit parquet, describing a different digest and a different row count. A
    result that cannot be tied to the code that produced it is not a result.
    """
    root = Path(__file__).resolve().parents[1]
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        commit = "nogit"
    h = hashlib.sha256()
    for path in sorted((root / "chakra").rglob("*.py")):
        h.update(path.relative_to(root).as_posix().encode())
        h.update(path.read_bytes())
    return f"{commit}-{h.hexdigest()[:8]}"


def _config_hash(cfg) -> str:
    payload = {
        k: (v.value if hasattr(v, "value") else v)
        for k, v in sorted(vars(cfg).items())
    }
    return hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()[:8]


def _write_atomic(path: Path, text: str) -> None:
    """Write via a temp file and replace, so a crash mid-write cannot leave a
    half-written manifest that later reads as authoritative."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def run_one(family_code: str, seed: int, generations: int, small: bool):
    cfg = LoopConfig(
        seed=seed,
        generations=generations,
        pop_params=6 if small else 10,
        n_consumers=200 if small else 400,
        n_merchants=20 if small else 40,
        world_span_days=1.5 if small else 3.0,
    )
    loop = Loop(ATTACK_FAMILIES[family_code], cfg)

    # Run directory is keyed on code version and config as well as seed, so a
    # score can never land beside an audit produced by different code.
    code_v = _code_version()
    out = RUNS / f"{family_code}_seed{seed}_{code_v}_{_config_hash(cfg)}"

    # Seal the audit set AND persist it before the loop trains anything, so the
    # sealed evaluation set demonstrably exists independently of the result.
    init_params = loop.proposer.initial(Rng(seed, tag="auditinit"), cfg.pop_params)
    audit = loop.build_locked_audit(init_params)
    audit.save(out)

    results = loop.run()

    final_params = [results[-1].best_params] if results and results[-1].best_params else init_params
    bundle, threshold = loop.score_locked_audit(Rng(seed + 999, tag="auditscore"), final_params, out)

    (out / "generations.json").write_text(
        json.dumps(
            [
                {
                    "generation": r.generation,
                    "episode_evasion": r.episode_evasion,
                    "attacker_yield": r.attacker_yield,
                    "recall_pre": r.monitor_recall_pre,
                    "recall_post": r.monitor_recall_post,
                    "fpr_pre": r.monitor_fpr_pre,
                    "fpr_post": r.monitor_fpr_post,
                    "prevalence": r.prevalence,
                    "n_episodes": r.n_episodes,
                    "best_params": r.best_params,
                }
                for r in results
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_atomic(
        out / "audit_score.json",
        json.dumps(
            {
                "threshold": threshold,
                "metrics": bundle.to_dict(),
                "audit_digest": audit.digest,
                "code_version": code_v,
                "seed": seed,
                "family": family_code,
            },
            indent=2,
            default=float,
        ),
    )
    return results, bundle, audit


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", default="F11")
    ap.add_argument("--seeds", type=int, nargs="*", default=[1000, 1001, 1002, 1003, 1004])
    ap.add_argument("--generations", type=int, default=6)
    ap.add_argument("--small", action="store_true", help="smaller world, faster")
    args = ap.parse_args()

    per_seed = []
    for seed in args.seeds:
        results, bundle, audit = run_one(args.family, seed, args.generations, args.small)
        per_seed.append((seed, results, bundle))
        print(f"seed {seed}: sealed audit {audit.digest[:12]} | {bundle.headline()}")

    print(f"\n{args.family} across {len(args.seeds)} seeds — median [IQR]\n")

    def summarise(label, values):
        v = np.array(values, dtype=float)
        q1, med, q3 = np.percentile(v, [25, 50, 75])
        print(f"  {label:<26} {med:>7.3f}  [{q1:.3f} - {q3:.3f}]")

    last = [r[-1] for _, r, _ in per_seed]
    summarise("final episode evasion", [x.episode_evasion for x in last])
    summarise("final attacker yield", [x.attacker_yield for x in last])
    summarise("final recall (pre)", [x.monitor_recall_pre for x in last])
    summarise("final recall (post)", [x.monitor_recall_post for x in last])
    summarise("audit AUPRC", [b.auprc for _, _, b in per_seed])
    # Labelled with the FPR the frozen cut ACTUALLY achieved, not the budget it
    # was aiming at. A tie-safe cut is often well inside the budget, and calling
    # the result "recall@0.5%FPR" when the realised rate is 0.13% overstates how
    # much alert volume was spent to get it.
    summarise("audit recall @frozen cut", [b.recall_at_0_5pct_fpr for _, _, b in per_seed])
    summarise("  realised FPR at that cut", [b.achieved_fpr_at_0_5pct_cut for _, _, b in per_seed])
    summarise("  (budget was)", [0.005 for _ in per_seed])
    summarise("audit prevalence", [b.prevalence for _, _, b in per_seed])

    print("\nevolved parameters at final generation, per seed:")
    names = sorted({k for _, r, _ in per_seed for k in (r[-1].best_params or {})})
    if names:
        print("  " + "seed".ljust(8) + "".join(n[:16].rjust(18) for n in names))
        for seed, r, _ in per_seed:
            bp = r[-1].best_params or {}
            print("  " + str(seed).ljust(8) + "".join(f"{bp.get(n, float('nan')):18.2f}" for n in names))
        print("\n  Read the spread, not any single row. A direction that does not")
        print("  reproduce across seeds is not a finding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
