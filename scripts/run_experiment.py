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
import json
from pathlib import Path

import numpy as np

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.generate.rng import Rng
from chakra.loop.orchestrator import Loop, LoopConfig

RUNS = Path(__file__).resolve().parents[1] / "runs"


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

    out = RUNS / f"{family_code}_seed{seed}"

    # Seal the audit set AND persist it before the loop trains anything, so the
    # sealed evaluation set demonstrably exists independently of the result.
    init_params = loop.proposer.initial(Rng(seed, tag="auditinit"), cfg.pop_params)
    audit = loop.build_locked_audit(init_params)
    audit.save(out)

    results = loop.run()

    final_params = [results[-1].best_params] if results and results[-1].best_params else init_params
    bundle, threshold = loop.score_locked_audit(Rng(seed + 999, tag="auditscore"), final_params)

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
    (out / "audit_score.json").write_text(
        json.dumps(
            {"threshold": threshold, "metrics": bundle.to_dict(), "audit_digest": audit.digest},
            indent=2,
            default=float,
        ),
        encoding="utf-8",
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
    summarise("audit recall@0.5%FPR", [b.recall_at_0_5pct_fpr for _, _, b in per_seed])
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
