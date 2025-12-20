from pathlib import Path
import re
from slither.slither import Slither
from slither.utils.tests_pattern import is_test_file
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.tools.agent.model_contract import CallEdge, CallGraph, ContractIR

def get_contract_irs(s: Slither) -> list[ContractIR]:
    """Analyze contracts and build ContractIR summaries."""
    ir_contracts = []
    for c in s.contracts_derived:
        # Skip unsuitable contracts
        file_path = c.source_mapping.filename.absolute
        if (
            c.is_abstract
            or c.is_test
            or c.is_library
            or c.is_interface
            or c.is_from_dependency()
            or "node_modules" in file_path
            or is_test_file(Path(file_path))
        ):
            continue

        irc = ContractIR(contract_name = c.name)

        for e in c.events:
            content = re.sub(
                r"\s+", " ", e.source_mapping.content)
            irc.add_event(e.canonical_name, content.strip())

        for sv in c.state_variables:
            irc.add_state(sv.canonical_name,
                sv.source_mapping.content)
        
        parents = [p.name for p in c.inheritance]
        irc.inheritances = parents
        
        imports = {str(imp.filename_path)
            for imp in c.compilation_unit.import_directives}
        irc.imports.extend(imports)

        for func in c.functions_entry_points:
            # Skip getters / view / pure functions
            if (func.view or func.pure 
                or func.name in irc.state_vars):
                continue

            irc.add_entry(
                func.canonical_name,
                get_function_summary(func))

            graph = CallGraph()
            build_graph(func, graph)
            irc.add_call_graph(func.canonical_name, graph)

        ir_contracts.append(irc)
    return ir_contracts

def get_function_summary(func: Function) -> str:
    """Get the definition of a function."""
    name = func.name or func.type
    params = ", ".join(
        f"{str(p.type)} {p.name}".strip()
        for p in func.parameters
    )
    modifiers = " ".join(m.name for m in func.modifiers)
    if func.returns:
        returns = "returns (" + ", ".join(
            str(r.type) for r in func.returns
        ) + ")"
    else:
        returns = ""
    
    mutables = []
    if func.payable:
        mutables.append("payable")
    if func.view:
        mutables.append("view")
    if func.pure:
        mutables.append("pure")
    mutables = " ".join(mutables)

    visibility = func.visibility or ""

    extras = []
    if getattr(func, "override", False):
        extras.append("override")
    if getattr(func, "virtual", False):
        extras.append("virtual")
    extra_str = " ".join(extras)

    sr = ", ".join(f"{str(s.type)} {s.name}" 
                   for s in func.state_variables_read)
    sw = ", ".join(f"{str(s.type)} {s.name}" 
                   for s in func.state_variables_written)
    if not sr:
        sr = "none"
    if not sw:
        sw = "none"
    
    parts = [
        f"function {name}({params})",
        visibility,
        mutables,
        modifiers,
        extra_str,
        returns
    ]
    header = " ".join(p for p in parts if p)
    summary = f"{header} /* reads: {sr}; writes: {sw} */"
    summary = re.sub(r"\s+", " ", summary).strip()

    return summary

def get_funcs_rw_state(s: Slither,
    contract_name: str, sv: str) -> list[str]:
    """Get functions that read/write a given state."""
    funcs = []
    for c in s.contracts_derived:
        if c.name != contract_name:
            continue
        for func in c.functions:
            f = ""
            for state_var in set(
                func.state_variables_written + 
                func.state_variables_read):
                if sv == state_var.canonical_name:
                    f = func.source_mapping.content
            for modifier in func.modifiers:
                for state_var in set(
                    modifier.state_variables_written + 
                    modifier.state_variables_read):
                    if sv == state_var.canonical_name:
                        f += modifier.source_mapping.content
            if f:
                funcs.append(f)
    return funcs

def get_sol_version(s: Slither, contract_name: str) -> str:
    """Get the Solidity version used by a contract."""
    for c in s.contracts_derived:
        if c.name != contract_name:
            continue
        return c.compilation_unit.solc_version

def build_graph(func: Function, graph: CallGraph,
                visited: set[str] | None = None) -> None:
    """Recursively build graph by following calls."""
    if visited is None:
        visited = set()
    er = func.canonical_name
    if er in visited:
        return
    visited.add(er)
    for ctype, calls in [
        ("INTERNAL_CALL", func.internal_calls),
        ("HIGH_LEVEL_CALL", func.high_level_calls)]:
        _process_calls(er, ctype, calls, graph, visited)

def _process_calls(er: str, ctype: str, calls,
    graph: CallGraph, visited: set[str]) -> None:
    """Process a collection of calls for a given caller."""
    for call in calls:
        # high_level_calls -> Tuple[Contract, HighLevelCall]
        if isinstance(call, tuple):
            _, call = call
        
        fcalled = call.function

        if isinstance(fcalled, SolidityFunction):
            continue

        edge_name = f"{er} -> {fcalled.canonical_name}"
        edge = CallEdge(
            call_type = ctype,
            caller_name = er,
            callee_name = fcalled.canonical_name,
            callee_snippet = fcalled.source_mapping.content,
        )
        graph.add_edge(edge_name, edge)
        if not isinstance(fcalled, StateVariable):
            build_graph(fcalled, graph, visited)