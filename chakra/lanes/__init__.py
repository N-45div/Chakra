"""Lane A — dataset-native synthetic-to-real validation.

Kept in its own package because it must never touch the Chakra simulator. The
experiment contract is explicit that the lanes are not conflated: Lane A
validates that a generator fitted on a real dataset produces rows a detector can
learn from, measured on a locked real test partition of that same dataset. It
says nothing whatever about the Indian attack families, and any wording that
implies otherwise is a misrepresentation.
"""

from chakra.lanes.tstr import LaneAResult, run_lane_a

__all__ = ["run_lane_a", "LaneAResult"]
