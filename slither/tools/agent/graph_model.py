import json
from enum import Enum, auto
import os
from typing import Optional
from dataclasses import asdict, dataclass, field, is_dataclass

class EntryType(Enum):
    NONE = auto()
    USER = auto()
    FALLBACK = auto()
    CONSTRUCTOR = auto()

class CallType(Enum):
    INTERNAL = auto()
    LOW_LEVEL = auto()
    HIGH_LEVEL = auto()

@dataclass
class Source:
    path: str
    lines: int
    snippet: str

@dataclass
class CallNode:
    sig: str
    source: Source
    permissions: str = ""

@dataclass
class CallEdge:
    caller: str
    callee: str
    source: Source
    call_type: CallType
    permission: str = ""

    def __hash__(self):
        return hash((self.caller, self.callee, self.call_type))

def dataclass_to_dict(obj):
    if is_dataclass(obj):
        return {k: dataclass_to_dict(v) for k, v in asdict(obj).items()}
    elif isinstance(obj, (list, set, tuple)):
        return [dataclass_to_dict(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
    elif isinstance(obj, Enum):
        return obj.name
    else:
        return obj

@dataclass
class CallGraph:
    entry_point: str = ""
    entry_type: EntryType = EntryType.NONE
    state_vars: dict[str, str] = field(default_factory=dict)
    nodes: dict[str, CallNode] = field(default_factory=dict)
    edges: dict[str, set[CallEdge]] = field(default_factory=dict)
    reversed_edges: dict[str, set[CallEdge]] = field(default_factory=dict)
    
    def set_entry(self, func_sig:str, entry_type: EntryType):
        self.entry_point = func_sig
        self.entryPtype = entry_type

    def add_state_var(self, name: str, expression: str):
        if not name:
            raise ValueError("State variable name cannot be empty.")
        self.state_vars[name] = expression

    def add_node(self, func_sig: str, data: Optional[Source] = None):
        if func_sig not in self.nodes:
            source = data or Source("", 0, "")
            node = CallNode(func_sig, source)
            self.nodes[func_sig] = node
            self.edges[func_sig] = set()
            self.reversed_edges[func_sig] = set()
        
    def add_edge(self, er: str, ee: str, data: Source, ty: CallType):
        if er not in self.nodes or ee not in self.nodes:
            raise ValueError(f"Undefined caller/callee: {er} -> {ee}")
        edge = CallEdge(er, ee, data, ty)
        self.edges[er].add(edge)
        self.reversed_edges[ee].add(edge)
    
    def get_successors(self, func_sig: str) -> list[str]:
        return [e.callee for e in self.edges.get(func_sig, set())]

    def get_predecessors(self, func_sig: str) -> list[str]:
        return [e.caller for e in self.reversed_edges.get(func_sig, set())]
    
    def print_graph(self):
        for _, edges in self.edges.items():
            for e in edges:
                print(f"{e.caller} -> {e.callee} ({e.call_type.name})")

    def dfs_from_entry(self, func_sig: str) -> list[str]:
        visited, order = set(), []
        def dfs(node: str):
            if node in visited:
                return
            visited.add(node)
            order.append(node)
            for callee in self.get_successors(node):
                dfs(callee)
        dfs(func_sig)
        return order
    
    def paths_to_entry(self, func_sig: str) -> list[list[str]]:
        if not self.entry_point:
            raise ValueError("Entry point not set.")
        paths, path = [], []
        def backtrack(node: str):
            path.append(node)
            if node == self.entry_point:
                paths.append(path[::-1])
            else:
                for caller in self.get_predecessors(node):
                    backtrack(caller)
            path.pop()
        backtrack(func_sig)
        return paths 
    
    def save(self, filename: str):
        if not self.entry_point:
            raise ValueError("Entry point not set, cannot save graph.")
        os.makedirs("output", exist_ok=True)
        file_path = os.path.join("output", f"{filename}.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(dataclass_to_dict(self), f, indent=2, ensure_ascii=False)
        print(f"[+] Saved call graph to {file_path}")

    @staticmethod
    def load(path: str) -> "CallGraph":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return CallGraph.from_dict(data)

    @staticmethod
    def from_dict(data: dict) -> "CallGraph":
        def to_source(d):
            return Source(d["path"], d["lines"], d["snippet"])

        graph = CallGraph(entry_point=data.get("entry_point", ""))
        graph.state_vars = data.get("state_vars", {})
        for sig, node in data.get("nodes", {}).items():
            graph.nodes[sig] = CallNode(
                sig,
                to_source(node["source"]),
                node.get("permissions", "")
            )
        for er, edges in data.get("edges", {}).items():
            graph.edges[er] = set()
            for e in edges:
                edge = CallEdge(
                    e["caller"], e["callee"],
                    to_source(e["source"]),
                    CallType[e["call_type"]],
                    e.get("permission", "")
                )
                graph.edges[er].add(edge)
                graph.reversed_edges.setdefault(edge.callee, set()).add(edge)
        return graph