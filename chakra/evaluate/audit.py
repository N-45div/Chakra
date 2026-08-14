"""The locked audit stream.

Built once from its own seed, hashed, written to disk, and scored exactly once
at the end of a run. Nothing in the loop may read it: not the proposer, not the
detector, not the threshold.

The hash is the point. A stream you promise not to look at is a claim; a stream
whose contents are pinned by a hash recorded before the run, and re-verified
before scoring, is a property. If the audit data changed between construction
and scoring — because a generator was edited, a seed moved, or someone
regenerated it after seeing a disappointing number — the hash check fails loudly
instead of the result quietly becoming meaningless.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd


@dataclass(frozen=True, slots=True)
class LockedAudit:
    """A frozen evaluation set plus the fingerprint that proves it is frozen."""

    features: pd.DataFrame
    labels: pd.Series
    meta: pd.DataFrame
    digest: str
    created_at: datetime
    seed: int
    family: str

    def verify(self) -> None:
        """Recompute the fingerprint and refuse to proceed if it moved."""
        current = _digest(self.features, self.labels, self.meta)
        if current != self.digest:
            raise RuntimeError(
                "locked audit stream has changed since it was sealed "
                f"(sealed {self.digest[:12]}, now {current[:12]}). "
                "A result scored on a mutated audit set is not a result."
            )

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        self.features.to_parquet(directory / "audit_features.parquet")
        self.labels.to_frame().to_parquet(directory / "audit_labels.parquet")
        self.meta.to_parquet(directory / "audit_meta.parquet")
        manifest = {
            "digest": self.digest,
            "created_at": self.created_at.isoformat(),
            "seed": self.seed,
            "family": self.family,
            "n_rows": int(len(self.labels)),
            "n_fraud": int(self.labels.sum()),
            "prevalence": float(self.labels.mean()),
        }
        (directory / "audit_manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return directory / "audit_manifest.json"


def _digest(features: pd.DataFrame, labels: pd.Series, meta: pd.DataFrame) -> str:
    h = hashlib.sha256()
    h.update(pd.util.hash_pandas_object(features, index=True).values.tobytes())
    h.update(pd.util.hash_pandas_object(labels, index=True).values.tobytes())
    h.update(pd.util.hash_pandas_object(meta["event_id"], index=True).values.tobytes())
    return h.hexdigest()


def seal_audit(features, labels, meta, seed: int, family: str, created_at: datetime) -> LockedAudit:
    """Seal an evaluation set. `created_at` is passed in rather than read from
    the clock so a whole run stays reproducible."""
    return LockedAudit(
        features=features,
        labels=labels,
        meta=meta,
        digest=_digest(features, labels, meta),
        created_at=created_at,
        seed=seed,
        family=family,
    )
