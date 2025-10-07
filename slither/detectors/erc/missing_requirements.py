from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector, DetectorClassification, DETECTOR_INFO)

class MissingRequirements(AbstractDetector):
    """
    检测模式：
    - 定位合约中对NFT的授权(_approve)和销毁(_burn)操作。
    - 检查相关函数是否有权限保护。
    """

    ARGUMENT = "missing-requirements"
    HELP = "Detect missing requirements in functions that call _approve or _burn"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."
    results = []

    def _detect(self) -> list[Output]:
        
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_entry_points:
                if func.is_constructor:
                    continue
                if self.check_apprrove(func) and func.name not in ["transferFrom","safeTransferFrom"]:
                    info: DETECTOR_INFO = ["vulnerability detected: ",
                        func," set approval but lacks permission checks.\n"]
                    res = self.generate_result(info)
                    self.results.append(res)
                for incall in func.internal_calls:
                    if incall.function and incall.function.name == "_burn":
                        if func.name != "_burn" and not func.is_access_controlled():
                            info: DETECTOR_INFO = ["vulnerability detected: ",
                                func," calls _burn but lacks permission checks.\n"]
                            res = self.generate_result(info)
                            self.results.append(res)
        return self.results
    
    def check_apprrove(self, func):
        if hasattr(func, "state_variables_written"):
            for state_var in func.state_variables_written:
                if state_var.name == "_tokenApprovals":
                    if not func.is_access_controlled():
                        return True
        if hasattr(func, "internal_calls"):
            for incall in func.internal_calls:
                if incall.function and "burn" not in incall.function.name and self.check_apprrove(incall.function):
                    if not func.is_access_controlled():
                        return True
        return False
