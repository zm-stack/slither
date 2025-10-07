from operator import call
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO)
from slither.core.declarations.function import Function

class ERC721Reentrancy(AbstractDetector):
    """
    - function calls EXTERNAL_CALL and also writes state variables
    - if the position of the call appears before state write, it reports a potential vulnerability
    """
    ARGUMENT = "erc721-reentrancy"
    HELP = "Detect potential ERC-721 reentrancy where onERC721Received may reenter due to state updates after safe calls"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    INTERNAL_CALL = ["_safeMint", "_safeBatchMint", "safeTransferFrom", "safeBatchTransferFrom"]

    def _detect(self) -> list[Output]:
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                guarded = False
                for modifier in func.modifiers:
                    name = modifier.name.lower()
                    if "reentr" in name or "only" in name:
                        guarded = True
                if guarded:
                    continue
                callline = self._check_call(func)
                writeline = self._check_write(func)
                if callline:
                    if not writeline:
                        info: DETECTOR_INFO = ["vulnerability detected: ",
                            func, " makes a external call but not updating state, ",
                            " where onERC721Received may reenter.\n"]
                        res = self.generate_result(info)
                        results.append(res)
                    if writeline and callline < writeline:
                        print("callline", callline, "writeline", writeline)
                        info: DETECTOR_INFO = ["vulnerability detected: ",
                            func, " makes a external call before updating state, ",
                            " where onERC721Received may reenter.\n"]
                        res = self.generate_result(info)
                        results.append(res)
        return results
    
    def _check_call(self, func:Function) -> int | None:
        if hasattr(func, "internal_calls"):
            for incall in func.internal_calls:
                if incall.function:
                    if incall.function.name in self.INTERNAL_CALL or self._check_call(incall.function):
                        return incall.expression.source_mapping.lines[0] # type: ignore
        return None
                    
    def _check_write(self, func:Function) -> int | None:
        lines = []
        if hasattr(func, "nodes"):
            for node in func.nodes:
                if node.state_variables_written:
                    lines.append(node.source_mapping.lines[0])  # type: ignore
        if hasattr(func, "internal_calls"):
            for incall in func.internal_calls:
                if incall.function and self._check_write(incall.function):
                    lines.append(incall.expression.source_mapping.lines[0]) # type: ignore
        return max(lines) if lines else None