from pathlib import Path
from slither.slither import Slither
from slither.utils.tests_pattern import is_test_file
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.tools.agent.graph_model import CallGraph, CallType, EntryType

def get_entry_points(s: Slither) -> set[FunctionContract]:
    """
    Collect entry functions from the contracts.

    Filters out:
      - Abstract contracts
      - Test contracts/files
      - Libraries, interfaces
      - Contracts from dependencies

    Also skips:
      - pure/view functions
      - functions whose names collide with state names
    """
    entry_points = set()
    for c in s.contracts:
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

def build_graphs(entries: set[FunctionContract]) -> set[CallGraph]:
    graphs = set()
    for entry in entries:
        graph = CallGraph()
        graph.name = (entry.contract.name + "_" + entry.name)
        print(f"Building call graph: {graph.name}")
        sig = entry.canonical_name
        
        # Set entry point properties
        if entry.is_constructor:
            graph.set_entry(sig, EntryType.CONSTRUCTOR_ENTRY)
        elif entry.is_fallback:
            graph.set_entry(sig, EntryType.FALLBACK_ENTRY)
        else:
            graph.set_entry(sig, EntryType.USER_DEFINED_ENTRY)
        graph.add_node(sig, entry.source_mapping.content)
        
        # Register all state variables
        for state_var in entry.contract.state_variables:
            graph.add_state_var(state_var.name,
                state_var.source_mapping.content)

        # Expand the graph starting from this entry point
        extend_graph(entry, graph)
        graphs.add(graph)
    return graphs
    
def extend_graph(func: Function, graph: CallGraph) -> None:
    """Recursively extend the graph by following function calls."""
    caller = func.canonical_name
    for call_type, calls in [
        (CallType.INTERNAL_FUNCTION_CALL, func.internal_calls),
        (CallType.HIGH_LEVEL_FUNCTION_CALL, func.high_level_calls)]:
        _process_calls(call_type, calls, caller, graph)

def _process_calls(call_type: CallType, calls,
                   caller_sig: str, graph: CallGraph) -> None:
    """Process a collection of calls for a given caller."""
    for call in calls:
        # high_level_calls -> Tuple[Contract, HighLevelCall]
        if isinstance(call, tuple):
            _, call = call
        
        if isinstance(call.function, SolidityFunction):
            continue
        callee_func = call.function
        callee_sig = getattr(callee_func, "canonical_name",
            getattr(callee_func, "name", None))
        callee_snippet = callee_func.source_mapping.content
        call_snippet = call.expression.source_mapping.content
        graph.add_node(callee_sig, callee_snippet)
        graph.add_edge(caller_sig, callee_sig, call_snippet, call_type)
        if not isinstance(callee_func, StateVariable):
            extend_graph(callee_func, graph)