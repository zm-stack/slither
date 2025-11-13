"""
Module printing augmented call graph of the contracts
"""

from pathlib import Path
from slither.utils.output import Output
from slither.utils.tests_pattern import is_test_file
from slither.printers.abstract_printer import AbstractPrinter
from slither.printers.augmented_call.model import (
    CallGraph, CallType, Source, EntryType
)
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.slithir.operations.low_level_call import LowLevelCall


class PrinterAugmentedCallGraph(AbstractPrinter):

    ARGUMENT = "augmented-call-graph"
    HELP = "Print augmented call graph of the contracts"
    WIKI = "..."

    def output(self, filename: str) -> Output:
        for contract in self.contracts:
            if (
                contract.is_abstract or
                contract.is_test or
                contract.is_library or
                contract.is_interface or
                contract.is_from_dependency() or
                is_test_file(
                    Path(contract.source_mapping.filename.absolute))
            ):
                continue
            for func in contract.functions_entry_points:
                if (
                    func.view or
                    func.pure or
                    func.name in [
                        v.name for v in contract.state_variables]
                ):
                    continue

                graph = CallGraph()
                if func.is_constructor:
                    graph.set_entry(
                        func.canonical_name,
                        EntryType.CONSTRUCTOR
                    )
                if func.is_fallback:
                    graph.set_entry(
                        func.canonical_name,
                        EntryType.FALLBACK
                    )
                else:
                    graph.set_entry(
                        func.canonical_name,
                        EntryType.USER
                    )
    
                for svar in func.contract.state_variables:
                    graph.add_state_var(
                        svar.name,
                        svar.source_mapping.content
                    )
                graph.add_node(
                    func.canonical_name,
                    self._to_source(func)
                )
                self.build_graph(func, graph)
                graph.save(func.contract.name+"_"+func.name)

        self.info("Success.")
        return self.generate_output("Success.")
            
    def build_graph(self, func:Function, graph: CallGraph):
        caller = func.canonical_name
        for call_type, calls in [
            (CallType.INTERNAL, func.internal_calls),
            (CallType.HIGH_LEVEL, func.high_level_calls),
            (CallType.LOW_LEVEL, func.low_level_calls),
        ]:
            self._process_calls(calls, caller, graph, call_type)

    def _process_calls(self, calls, caller, graph, call_type) -> None:
        for call in calls:
            # high_level_calls returns Tuple[Contract, HighLevelCall]
            if isinstance(call, tuple):
                _, call = call

            expr = call.expression
            callee_sig = expr.source_mapping.content
            source = self._to_source(expr)

            if isinstance(call, LowLevelCall):
                graph.add_node(callee_sig)
                graph.add_edge(caller, callee_sig, source, call_type)
            elif isinstance(call.function, SolidityFunction):
                continue
            else:
                callee = call.function
                callee_sig = getattr(
                    callee, "canonical_name",
                    getattr(callee, "name", None)
                )
                graph.add_node(callee_sig, self._to_source(callee))
                graph.add_edge(caller, callee_sig, source, call_type)
                if not isinstance(callee, StateVariable):
                    self.build_graph(callee, graph)
    
    def _to_source(self, obj):
        sm = getattr(obj, "source_mapping", None)

        lines = getattr(sm, "lines", 0)
        if lines and isinstance(lines, list):
            lines = [min(lines), max(lines)]
        elif isinstance(lines, int):
            lines = [lines, lines]
        else:
            lines = [0, 0]

        return Source(
            path = getattr(getattr(sm, "filename", None), "used", ""),
            lines = lines,
            snippet = getattr(sm, "content", ""),
        )
