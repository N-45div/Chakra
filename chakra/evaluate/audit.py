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


@dataclass(slots=True)
class LockedAudit:
    """A frozen evaluation set plus the fingerprint that proves it is frozen.

    Three properties the earlier version claimed but did not have:
      - the digest covers every field that affects a reported number, not just
        event_id;
      - it is written to disk BEFORE the loop trains anything, so the sealed set
        exists independently of the result;
      - it can be scored exactly once, and refuses to overwrite an existing seal.
    """

    features: pd.DataFrame
    labels: pd.Series
    meta: pd.DataFrame
    digest: str
    created_at: datetime
    seed: int
    family: str
    rail: str = "card"
    _scored: bool = False

    def verify(self) -> None:
        """Recompute the fingerprint and refuse to proceed if it moved."""
        current = _digest(self.features, self.labels, self.meta)
        if current != self.digest:
            raise RuntimeError(
                "locked audit stream has changed since it was sealed "
                f"(sealed {self.digest[:12]}, now {current[:12]}). "
                "A result scored on a mutated audit set is not a result."
            )

    def claim_scoring(self, directory: Path | None = None) -> None:
        """Consume the single permitted scoring.

        The in-memory flag alone was process-local: a fresh interpreter reset it,
        so "scored once" held only within a single run. When a directory is
        given, a `scored.marker` file makes the claim durable, which is the only
        version that stops a disappointing number being quietly re-rolled.
        """
        if self._scored:
            raise RuntimeError(
                "locked audit stream has already been scored once in this process."
            )
        marker = (directory / "scored.marker") if directory else None
        if marker is not None and marker.exists():
            raise RuntimeError(
                f"locked audit stream at {directory} was already scored "
                f"(marker written {marker.read_text(encoding='utf-8').strip()}). "
                "Build a new audit set from a new seed rather than re-scoring."
            )
        self.verify()
        self._scored = True
        if marker is not None:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(f"digest={self.digest}", encoding="utf-8")

    def save(self, directory: Path, allow_overwrite: bool = False) -> Path:
        manifest_path = directory / "audit_manifest.json"
        if manifest_path.exists() and not allow_overwrite:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            if existing.get("digest") != self.digest:
                raise RuntimeError(
                    f"refusing to overwrite a different sealed audit at {directory} "
                    f"(on disk {str(existing.get('digest'))[:12]}, "
                    f"this one {self.digest[:12]})"
                )
            return manifest_path
        directory.mkdir(parents=True, exist_ok=True)
        self.features.to_parquet(directory / "audit_features.parquet")
        self.labels.to_frame().to_parquet(directory / "audit_labels.parquet")
        self.meta.to_parquet(directory / "audit_meta.parquet")
        manifest = {
            "digest": self.digest,
            "digested_columns": list(_DIGESTED_META),
            "created_at": self.created_at.isoformat(),
            "seed": self.seed,
            "family": self.family,
            "rail": self.rail,
            "n_rows": int(len(self.labels)),
            "n_fraud": int(self.labels.sum()),
            "prevalence": float(self.labels.mean()),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest_path


# Every meta column that can change a reported number. amount_inr drives
# value-weighted recall; family drives per-family and worst-family recall; rail
# scopes the population. An earlier digest covered only event_id, so both
# amount_inr and family could be rewritten in place and verify() still passed —
# the seal proved nothing about the figures computed from it.
_DIGESTED_META = ("event_id", "amount_inr", "family", "rail")


def _digest(features: pd.DataFrame, labels: pd.Series, meta: pd.DataFrame) -> str:
    h = hashlib.sha256()
    # Column NAMES and dtypes, not just values. Renaming feature columns changes
    # what the model is fed while leaving every value untouched, and the earlier
    # digest passed verification straight through that.
    h.update("|".join(map(str, features.columns)).encode())
    h.update("|".join(str(d) for d in features.dtypes).encode())
    h.update(pd.util.hash_pandas_object(features, index=True).values.tobytes())
    h.update(pd.util.hash_pandas_object(labels, index=True).values.tobytes())
    for col in _DIGESTED_META:
        if col in meta.columns:
            h.update(col.encode())
            h.update(pd.util.hash_pandas_object(meta[col], index=True).values.tobytes())
    return h.hexdigest()


def seal_audit(
    features, labels, meta, seed: int, family: str, created_at: datetime, rail: str = "card"
) -> LockedAudit:
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
        rail=rail,
    )
