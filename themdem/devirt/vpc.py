"""Heuristic Virtual Program Counter (VPC) identification.

The VPC is the register/memory slot the interpreter uses to index the VM
bytecode stream. Following VMDoctor/Pushan, we identify it by watching, across
emulated interpreter steps, for a location that (a) holds a pointer into the
bytecode region and (b) evolves *sequentially* (monotonically advances through
that region). This module is engine-agnostic: it consumes snapshots of register
values and returns ranked VPC candidates.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Range:
    start: int
    end: int  # exclusive

    def contains(self, value: int) -> bool:
        return self.start <= value < self.end


@dataclass
class VPCCandidate:
    location: str  # register name, or "mem:0x..." for a fixed memory slot
    observations: int = 0
    monotonic_steps: int = 0
    values: List[int] = field(default_factory=list)

    @property
    def score(self) -> float:
        if self.observations < 2:
            return 0.0
        # Reward locations that stay inside the bytecode region and advance
        # in one direction.
        return self.monotonic_steps / max(self.observations - 1, 1)


class VPCTracker:
    """Accumulate register snapshots and rank VPC candidates."""

    def __init__(self, bytecode: Range) -> None:
        self.bytecode = bytecode
        self._candidates: Dict[str, VPCCandidate] = {}
        self._last: Dict[str, int] = {}
        self._direction: Dict[str, int] = defaultdict(int)

    def observe(self, snapshot: Dict[str, int]) -> None:
        """Record one snapshot mapping location name -> value."""
        for loc, value in snapshot.items():
            if not self.bytecode.contains(value):
                continue
            cand = self._candidates.setdefault(loc, VPCCandidate(location=loc))
            cand.observations += 1
            cand.values.append(value)
            if loc in self._last:
                delta = value - self._last[loc]
                if delta != 0:
                    step_dir = 1 if delta > 0 else -1
                    prior = self._direction[loc]
                    if prior == 0 or prior == step_dir:
                        cand.monotonic_steps += 1
                        self._direction[loc] = step_dir
            self._last[loc] = value

    def ranked(self) -> List[VPCCandidate]:
        cands = [c for c in self._candidates.values() if c.observations >= 2]
        cands.sort(key=lambda c: (c.score, c.observations), reverse=True)
        return cands

    def best(self) -> Optional[VPCCandidate]:
        ranked = self.ranked()
        return ranked[0] if ranked else None
