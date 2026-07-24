import json
from dataclasses import asdict, dataclass, field

@dataclass(frozen=True)
class ACRule:
    """Access control rule of a function node.
    
    Attributes:
        subject: Who performs the action.
        action: What action is done.
        object: Which resource is affected.
        condition: Under what condition.
        provenance: Source of the rule.
    """
    subject: str
    action: str
    object: str
    condition: str
    provenance: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class CallEdge:
    """An edge representing a call in call graph.
    
    Attributes:
        caller_name: caller function canonical_name.
        callee_name: callee function canonical_name.
        callee_snippet: code snippet of the call.
        callee_ac: inferred access control of callee.
    Notes:
        - low_level_calls are not modeled.
        - library_calls are in HIGH_LEVEL_CALL.
        - solidity_calls are in INTERNAL_CALL and are ignored.
    """
    call_type: str
    caller_name: str
    callee_name: str
    callee_snippet: str
    callee_ac: list[ACRule] = field(default_factory=list)

    def to_dict(self, include_snippet: bool = True) -> dict:
        """Convert edge to a serializable dict."""
        d = {
            "call_type": self.call_type,
            "caller_name": self.caller_name,
            "callee_name": self.callee_name,
            "callee_ac": [p.to_dict()
                for p in self.callee_ac],
        }
        if include_snippet:
            d["callee_snippet"] = self.callee_snippet
        return d

@dataclass
class CallGraph:
    """Call graph rooted at a entry function.
    
    Attributes:
        edges: "caller_name -> callee_name" -> CallEdge.
        in_edges: function canonical_name
                    -> set of incoming edge names.
        out_edges: function canonical_name
                    -> set of outgoing edge names.
    """
    edges: dict[str, CallEdge] = field(default_factory=dict)
    in_edges: dict[str, set[str]] = field(default_factory=dict)
    out_edges: dict[str, set[str]] = field(default_factory=dict)

    def add_edge(self, edge_name: str, edge: CallEdge) -> None:
        """Add an edge to the call graph."""
        self.edges[edge_name] = edge
        self.out_edges.setdefault(
            edge.caller_name, set()).add(edge_name)
        self.in_edges.setdefault(
            edge.callee_name, set()).add(edge_name)

    def summary_dict(self) -> dict:
        """Dict summary of call graph for quick debug."""
        return {"edges": sorted(self.edges.keys())}

    def to_dict(self, include_snippet: bool = True) -> dict:
        """Convert call graph to a serializable dict."""
        return {
            "edges": {
                ename: edge.to_dict(
                    include_snippet=include_snippet)
                for ename, edge in self.edges.items()
            },
            "in_edges": {
                fname: sorted(enames)
                for fname, enames in self.in_edges.items()
            },
            "out_edges": {
                fname: sorted(enames)
                for fname, enames in self.out_edges.items()
            },
        }

@dataclass
class ContractModel:
    """Model of a contract.
    
    Attributes:
        name: contract name.
        version: solidity version.
        imports: list of imported contract paths.
        inheritances: list of inherited contract names.
        events: event canonical name -> event definition.
        state_vars: state canonical name -> state definition.
        modifiers: modifier canonical name -> modifier definition.
        entry_funcs: funcion canonical name -> function summary.
        entry_access: inferred access control for entry_func.
        call_graphs: entry funcion canonical name -> CallGraph.
        complexity: complexity of contract weighted in features.
        
        """
    name: str
    version: str
    imports: list[str] = field(default_factory=list)
    inheritances: list[str] = field(default_factory=list)
    events: dict[str, str] = field(default_factory=dict)
    state_vars: dict[str, str] = field(default_factory=dict)
    modifiers: dict[str, str] = field(default_factory=dict)
    entry_funcs: dict[str, str] = field(default_factory=dict)
    entry_access: dict[str, list[ACRule]] = field(default_factory=dict)
    call_graphs: dict[str, CallGraph] = field(default_factory=dict)

    def add_event(self, name: str, definition: str) -> None:
        """Add an event of the contract."""
        self.events[name] = definition

    def add_state(self, name: str, definition: str) -> None:
        """Add a state variable of the contract."""
        self.state_vars[name] = definition

    def add_modifier(self, name:str, definition: str) -> None:
        """Add a modifier of the contract."""
        self.modifiers[name] = definition

    def add_entry(self, name: str, summary: str) -> None:
        """Add an entry function of the contract."""
        self.entry_funcs[name] = summary

    def add_entry_ac(self, name: str,
                    ac: list[ACRule]) -> None:
        """Add access control for an entry function."""
        self.entry_access[name] = ac

    def add_call_graph(self, name: str,
                    cg: CallGraph) -> None:
        """Add a call graph for an entry function."""
        self.call_graphs[name] = cg

    def _summary_dict(self) -> dict:
        """Dict summary of ContractModel for quick debug."""
        return {
            "name": self.name,
            "imports": list(self.imports),
            "inheritances": list(self.inheritances),
            "events": list(self.events.keys()),
            "state_vars": list(self.state_vars.keys()),
            "entry_funcs": list(self.entry_funcs.keys()),
            "entry_ac": {
                cname: [ac.to_dict() for ac in acs]
                for cname, acs in self.entry_access.items()
            },
            "call_graphs": {
                cname: cg.summary_dict()
                for cname, cg in self.call_graphs.items()
            },
        }

    def __str__(self) -> str:
        """Human-readable summary when print(ContractModel)."""
        return json.dumps(
            self._summary_dict(),
            ensure_ascii=False,
            indent=2,
        )

    def to_dict(self, include_snippet: bool = True) -> dict:
        """Serialize ContractModel into a dict."""
        return {
            "name": self.name,
            "imports": list(self.imports),
            "inheritances": list(self.inheritances),
            "events": self.events,
            "state_vars": self.state_vars,
            "entry_funcs": self.entry_funcs,
            "entry_ac": {
                name: [ac.to_dict() for ac in acs]
                for name, acs in self.entry_access.items()
            },
            "call_graphs": {
                name: cg.to_dict(include_snippet)
                for name, cg in self.call_graphs.items()
            },
        }
