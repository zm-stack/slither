import os
import json
from enum import Enum, auto
from dataclasses import asdict, dataclass, field, is_dataclass

class EntryType(Enum):
    """Type of contract entry point."""
    NONE = auto()
    FALLBACK_ENTRY = auto()
    CONSTRUCTOR_ENTRY = auto()
    USER_DEFINED_ENTRY = auto()

class CallType(Enum):
    """Type of a call edge in the call graph.
    
    Note:
        low_level_calls are not modeled currently.
        library_calls are considered HIGH_LEVEL_FUNCTION_CALL.
        solidity_calls are considered INTERNAL_FUNCTION_CALL.
    """
    INTERNAL_FUNCTION_CALL = auto()
    HIGH_LEVEL_FUNCTION_CALL = auto()

@dataclass
class CallNode:
    """
    A function node in the call graph.

    Attributes:
        sig: canonical_name of the function.
        snippet: code snippet representing the function.
        permissions: Inferred permission string of the function.
    """
    sig: str
    snippet: str
    permissions: dict[str,str] = field(default_factory=dict)

@dataclass
class CallEdge:
    """An edge representing the call in the call graph."""
    sig: str
    caller: str
    callee: str
    snippet: str
    call_type: CallType

    def __hash__(self) -> int:
        # Allow putting CallEdge into sets.
        return hash(
            (self.caller, self.callee, self.call_type)
        )

@dataclass
class CallGraph:
    """Call graph rooted at a single entry point."""
    name: str = "" # contract name_entry function name
    entry_point: str = "" # entry function canonical_name
    entry_type: EntryType = EntryType.NONE
    # state variable name -> definition snippet
    state_vars: dict[str, str] = field(default_factory=dict)
    # func_sig -> CallNode
    nodes: dict[str, CallNode] = field(default_factory=dict)
    # edge signature (caller -> callee) -> CallEdge
    edges: dict[str, CallEdge] = field(default_factory=dict)
    # func_sig -> set of incoming CallEdge
    in_edges: dict[str, set[CallEdge]] = field(default_factory=dict)
    # func_sig -> set of outgoing CallEdge
    out_edges: dict[str, set[CallEdge]] = field(default_factory=dict)

    def __hash__(self) -> int:
        # Allow putting CallGraph into sets.
        return hash((self.entry_point, self.entry_type))
    
    def set_entry(self, sig:str, entry_type: EntryType) -> None:
        """Set the entry point of the call graph."""
        if not sig:
            raise ValueError("Entry signature cannot be empty.")
        self.entry_point = sig
        self.entry_type = entry_type

    def add_state_var(self, svname: str, expr: str) -> None:
        """Add a state variable definition in the graph."""
        if not svname:
            raise ValueError("State name cannot be empty.")
        self.state_vars[svname] = expr

    def add_node(self, sig: str, snippet: str) -> None:
        """
        Add a node for the given function signature.
        And initialize an empty edge set for the node.
        """
        if sig not in self.nodes:
            node = CallNode(sig, snippet)
            self.nodes[sig] = node
            self.in_edges[sig] = set()
            self.out_edges[sig] = set()
        
    def add_edge(
            self, er: str, ee: str,
            snippet: str, ty: CallType) -> None:
        """Add a call edge caller_sig -> callee_sig."""
        if er not in self.nodes:
            raise ValueError(f"Undefined caller:{er}->{ee}")
        elif ee not in self.nodes:
            raise ValueError(f"Undefined callee:{er}->{ee}")
        edge_name = er + " -> " + ee
        if edge_name not in self.edges:
            edge = CallEdge(edge_name, er, ee, snippet, ty)
            self.edges[edge_name] = edge
            self.out_edges[er].add(edge)
            self.in_edges[ee].add(edge)
    
    def print_brief_graph(self) -> None:
        """Print all edges in the graph."""
        for edge in self.edges.values():
            print(f"{edge.sig} ({edge.call_type})")

    def save(self) -> None:
        """Serialize the graph into a JSON file."""
        os.makedirs("output", exist_ok=True)
        file_path = os.path.join("output", f"{self.name}.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(
                dataclass_to_dict(self),
                f,
                indent=2,
                ensure_ascii=False
            )
        print(f"[+] Saved call graph to {file_path}")

def dataclass_to_dict(obj):
    """
    Recursively convert dataclasses into plain Python types
    so they can be JSON-serialized.
    """
    if is_dataclass(obj):
        return dataclass_to_dict(asdict(obj))
    elif isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [dataclass_to_dict(v) for v in obj]
    elif isinstance(obj, set):
        return [dataclass_to_dict(v) for v in obj]
    elif isinstance(obj, Enum):
        return obj.name
    else:
        return obj