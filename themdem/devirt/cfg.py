"""VPC-sensitive control-flow graph.

The key idea from Pushan (and Kinder's VPC sensitivity): a virtualized program's
CFG is recovered by labelling each basic block with *both* its native address
and the Virtual Program Counter (VPC) at entry. The same interpreter handler is
reached from many bytecode locations; distinguishing them by VPC un-flattens the
interpreter loop back into the original control flow.

Each ``(address, vpc)`` block is emulated at most once (bounding state growth);
additional incoming edges are recorded without re-emulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

#: A node identity: (native block address, virtual program counter).
NodeID = Tuple[int, int]


@dataclass
class Node:
    id: NodeID
    #: Native instruction addresses that make up the block, in order.
    instructions: List[int] = field(default_factory=list)
    #: Recovered VM opcode / handler label, if this block is a handler body.
    handler: Optional[str] = None
    #: Free-form lifted statements attached during lifting.
    lifted: List[str] = field(default_factory=list)

    @property
    def address(self) -> int:
        return self.id[0]

    @property
    def vpc(self) -> int:
        return self.id[1]


class VPCSensitiveCFG:
    """A CFG whose nodes are keyed by ``(address, vpc)``."""

    def __init__(self) -> None:
        self._nodes: Dict[NodeID, Node] = {}
        self._succ: Dict[NodeID, Set[NodeID]] = {}
        self._pred: Dict[NodeID, Set[NodeID]] = {}
        self.entry: Optional[NodeID] = None

    # -- construction --------------------------------------------------------
    def add_node(self, node_id: NodeID) -> Node:
        """Return the node for ``node_id``, creating it if new."""
        node = self._nodes.get(node_id)
        if node is None:
            node = Node(id=node_id)
            self._nodes[node_id] = node
            self._succ[node_id] = set()
            self._pred[node_id] = set()
            if self.entry is None:
                self.entry = node_id
        return node

    def add_edge(self, src: NodeID, dst: NodeID) -> None:
        self.add_node(src)
        self.add_node(dst)
        self._succ[src].add(dst)
        self._pred[dst].add(src)

    def has_node(self, node_id: NodeID) -> bool:
        return node_id in self._nodes

    # -- queries -------------------------------------------------------------
    def node(self, node_id: NodeID) -> Node:
        return self._nodes[node_id]

    def successors(self, node_id: NodeID) -> Set[NodeID]:
        return self._succ.get(node_id, set())

    def predecessors(self, node_id: NodeID) -> Set[NodeID]:
        return self._pred.get(node_id, set())

    def nodes(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    def __len__(self) -> int:
        return len(self._nodes)

    # -- analysis ------------------------------------------------------------
    def vpc_values(self) -> Set[int]:
        """Distinct VPC values seen — i.e. recovered original instructions."""
        return {nid[1] for nid in self._nodes}

    def reachable_from(self, start: Optional[NodeID] = None) -> Set[NodeID]:
        start = start if start is not None else self.entry
        if start is None:
            return set()
        seen: Set[NodeID] = set()
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self._succ.get(cur, ()))
        return seen

    def topological_by_vpc(self) -> List[Node]:
        """Nodes ordered by VPC then address — the recovered program order."""
        return sorted(self._nodes.values(), key=lambda n: (n.vpc, n.address))

    def to_dot(self) -> str:
        lines = ["digraph vpc_cfg {", '  node [shape=box fontname="monospace"];']
        for nid, node in self._nodes.items():
            label = f"0x{nid[0]:x}@vpc:0x{nid[1]:x}"
            if node.handler:
                label += f"\\n{node.handler}"
            lines.append(f'  "{nid}" [label="{label}"];')
        for src, dsts in self._succ.items():
            for dst in dsts:
                lines.append(f'  "{src}" -> "{dst}";')
        lines.append("}")
        return "\n".join(lines)
