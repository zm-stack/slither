from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations.internal_call import InternalCall
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector, DetectorClassification, DETECTOR_INFO)

class UnlimitedMinting(AbstractDetector):
    """
    检测模式：
    - 定位所有对铸造函数的调用
    - 查看铸造前是否检查名为supply / totol的状态变量
    - 检查这些状态变量是否会被修改
    """

    ARGUMENT = "unlimited-minting"
    HELP = "Detect potential 'Unlimited Minting' where user can mint beyond max supply"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."
    results = []

    def _detect(self) -> list[Output]:
        supplyVar = []
        for contract in self.compilation_unit.contracts_derived:
            for stateVar in contract.state_variables:
                name = stateVar.name.lower() if stateVar.name else ""
                if "max" in name and "supply" in name:
                    supplyVar.append(stateVar)
                    self.check_state_modify(stateVar)
            for func in contract.functions_declared:
                supplycheck = False
                if func.is_constructor:
                    continue
                for mod in func.modifiers:
                    if isinstance(mod, Function):
                        for var in mod.state_variables_read:
                            if hasattr(var,"name") and var.name:
                                name = var.name.lower()
                                if "supply" in name or "total" in name or "max" in name or "limit" in name:
                                    supplycheck = True
                for node in func.nodes:
                    if node.is_conditional(False):
                        cond_vars = node.variables_read
                        for var in cond_vars:
                            if hasattr(var,"name") and var.name:
                                name = var.name.lower()
                                if "supply" in name or "total" in name or "max" in name or "limit" in name:
                                    supplycheck = True
                        for call in node.internal_calls:
                            if call.function and hasattr(call.function, "state_variables_read"):
                                for var in call.function.state_variables_read:
                                    name = var.name.lower() if var.name else ""
                                    if "supply" in name or "total" in name or "max" in name or "limit" in name:
                                        supplycheck = True
                    for ir in node.irs:
                        if isinstance(ir, InternalCall) and isinstance(ir.function, Function):
                            if (ir.function.name in ["_mint", "_safeMint", "_mintBatch"] or
                                self.check_mint(ir.function)):
                                if not supplycheck:
                                    info: DETECTOR_INFO = ["vulnerability detected: ",
                                        func, " mint NFTS but there is no supply check.\n"]
                                    res = self.generate_result(info)
                                    self.results.append(res)  
        return self.results
    
    def check_state_modify(self, stateVar:StateVariable):
        for func in self.compilation_unit.functions:
            if stateVar in func.state_variables_written:
                info: DETECTOR_INFO = ["vulnerability detected: supply variable ",
                    stateVar," can be modified in function ", func, ".\n"]
                res = self.generate_result(info)
                self.results.append(res)

    def check_mint(self, func:Function):
        if hasattr(func, "internal_calls"):
            for incall in func.internal_calls:
                if incall.function:
                    if incall.function in ["_mint", "_safeMint", "_mintBatch"]:
                        return True
                    else:
                        if self.check_mint(incall.function):
                            return True
            return False