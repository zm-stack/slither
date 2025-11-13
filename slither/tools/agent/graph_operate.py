
from pathlib import Path
from slither.core.declarations.function import Function
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.variables.state_variable import StateVariable
from slither.slither import Slither
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.tools.agent.graph_model import CallGraph, CallType, EntryType, Source
from slither.utils.tests_pattern import is_test_file


def get_entry_points(
        slither: Slither) -> set[FunctionContract]:
    entry_points = set()
    for c in slither.contracts:
        if (c.is_abstract or
            c.is_test or
            c.is_library or
            c.is_interface or
            c.is_from_dependency() or
            is_test_file(
                Path(c.source_mapping.filename.absolute))):
            continue
        for func in c.functions_entry_points:
            if (func.view or
                func.pure or
                func.name in [
                    sv.name for sv in c.state_variables]):
                continue
            entry_points.add(func)
    return entry_points

def build_graphs(
        entry_points: set[FunctionContract]) -> set[CallGraph]:
    graphs = set()
    for entry_point in entry_points:
        graph = CallGraph()
        func_sig = entry_point.canonical_name
        
        if entry_point.is_constructor:
            graph.set_entry(func_sig, EntryType.CONSTRUCTOR)
        elif entry_point.is_fallback:
            graph.set_entry(func_sig, EntryType.FALLBACK)
        else:
            graph.set_entry(func_sig, EntryType.USER)
        graph.add_node(func_sig, _to_source(entry_point))
        
        for state_var in entry_point.contract.state_variables:
            graph.add_state_var(state_var.name,
                state_var.source_mapping.content)

        extend_graph(entry_point, graph)

def extend_graph(entry_point: Function, graph: CallGraph):
    caller = entry_point.canonical_name
    for call_type, calls in [
        (CallType.INTERNAL, entry_point.internal_calls),
        (CallType.HIGH_LEVEL, entry_point.high_level_calls),
        (CallType.LOW_LEVEL, entry_point.low_level_calls)]:
        _process_calls(call_type, calls, caller, graph)

def _process_calls(call_type, calls, caller, graph) -> None:
    for call in calls:
        # high_level_calls -> Tuple[Contract, HighLevelCall]
        if isinstance(call, tuple):
            _, call = call

        expr = call.expression
        callee = expr.source_mapping.content
        source = _to_source(expr)

        if isinstance(call, LowLevelCall):
            graph.add_node(callee)
            graph.add_edge(caller, callee, source, call_type)
        elif isinstance(call.function, SolidityFunction):
            continue
        else:
            callee_func = call.function
            callee = getattr(callee_func, "canonical_name",
                getattr(callee_func, "name", None))
            graph.add_node(callee, _to_source(callee_func))
            graph.add_edge(caller, callee, source, call_type)
            if not isinstance(callee, StateVariable):
                self.build_graph(callee, graph)

def _to_source(obj):
    source = getattr(obj, "source_mapping", None)
    lines = getattr(source, "lines", 0)
    if lines and isinstance(lines, list):
        lines = [min(lines), max(lines)]
    return Source(
        path = getattr(getattr(source,
            "filename", None),
            "used", ""),
        lines = lines,
        snippet = getattr(source, "content", ""),
    )