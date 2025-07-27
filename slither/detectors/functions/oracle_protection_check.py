
from logging import Logger
from typing import List, Union
from slither.slither import Slither
from slither.utils.output import Output
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.slithir.operations.library_call import LibraryCall
from slither.slithir.operations.internal_call import InternalCall
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.type_conversion import TypeConversion
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO)
from slither.detectors.functions.oracle_data_check import (
    CH_ANYAPI_INIT, CH_ANYAPI_REQUEST, CH_FEED_APIS, CH_STREAM_VERIFY,
    CH_FUNCTIONS_REQUEST, CH_VRFDF_REQUEST, CH_VRFSUB_REQUEST, CHRONICLE_FEED_APIS,
    PYTH_FEED_SAFE_APIS, PYTH_FEED_UNSAFE_APIS, PYTH_FEED_UPDATE, PYTH_STREAM_VERIFY,
    PYTH_VRF_BUILD, PYTH_VRF_REQUEST, REDSTONE_FEED_APIS)

def check_state_protection(self, stateVar:StateVariable) -> None:
    for func in self.compilation_unit.functions:
        if stateVar in func.state_variables_written:
            if not func.is_access_controlled():
                info: DETECTOR_INFO = [
                    "CWE-284: state variable ", stateVar," in ", func, 
                    " lacks of access control.\n"]
                json = self.generate_result(info)
                self.results.append(json)

class OracleProtectionCheck(AbstractDetector):
    """
    Documentation
    """
    ARGUMENT = 'oracle-protection-check'
    HELP = 'Absence of protection in ' \
    'consumer contracts of Chainlink, Chronicle, Pyth, RedStone oracles'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."


    ACCESS_CONTROL_INTERFACE = ["AggregatorV3Interface",
        "AccessControlledOffchainAggregator", "IVerifierProxy", "FunctionsClient",
        "VRFV2WrapperConsumerBase", "VRFConsumerBaseV2", "VRFCoordinatorV2Interface",
        "VRFV2PlusWrapperConsumerBase", "VRFConsumerBaseV2Plus", "IPyth", "PythLazer",
        "IEntropy", "IChronicle"]
    ACCESS_CONTROL_CALL = (CH_ANYAPI_INIT + CH_ANYAPI_REQUEST + CH_FUNCTIONS_REQUEST +
                           CH_VRFSUB_REQUEST + CH_VRFDF_REQUEST + PYTH_VRF_BUILD)

    INTERNAL_CALLS = (CH_ANYAPI_INIT + CH_ANYAPI_REQUEST +
                      CH_FUNCTIONS_REQUEST + CH_VRFDF_REQUEST + REDSTONE_FEED_APIS)

    HIGH_LEVEL_CALLS = (CH_FEED_APIS + CH_STREAM_VERIFY + CH_VRFSUB_REQUEST +
        PYTH_FEED_SAFE_APIS + PYTH_FEED_UNSAFE_APIS + PYTH_FEED_UPDATE + PYTH_STREAM_VERIFY +
        PYTH_VRF_BUILD + PYTH_VRF_REQUEST + CHRONICLE_FEED_APIS)

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: list[Output] = []

    def _detect(self) -> List[Output]:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                isVulnerable = False
                hcalls = [hcall for _, hcall in func.high_level_calls]
                calls = func.library_calls + func.internal_calls + hcalls
                for call in calls:
                    if self.check_call(call):
                        isVulnerable = True
                if isVulnerable:
                    if not self.is_pausable(func):
                        info: DETECTOR_INFO = [
                            "CWE-693: oracle operation in ", func,
                            " is not pausable.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if not contract.is_upgradeable:
                        info: DETECTOR_INFO = [
                            "CWE-693: oracle operation in ", contract,
                            " is not upgradeable.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, TypeConversion):
                            if str(ir.type) in self.ACCESS_CONTROL_INTERFACE:
                                if not func.is_access_controlled():
                                    info: DETECTOR_INFO = [
                                        "CWE-284: Interface instantiation in ",
                                        ir.node, " lacks of access control.\n"]
                                    json = self.generate_result(info)
                                    self.results.append(json)
                                for var in ir.node.state_variables_read:
                                    check_state_protection(self, var)
        return self.results

    def check_call(self, call:Union[LibraryCall, InternalCall, HighLevelCall]) -> bool:
        isVulnerable = False
        if isinstance(call.function, Function):
            fname = call.function.name
            if (fname in self.INTERNAL_CALLS or
                fname in self.HIGH_LEVEL_CALLS):
                isVulnerable = True
                for var in call.node.state_variables_read:
                    check_state_protection(self, var)
            if fname in self.ACCESS_CONTROL_CALL:
                if not call.node.function.is_access_controlled():
                    info: DETECTOR_INFO = [
                        "CWE-284: oracle operation ", call.node,
                        " lacks of access control.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
        return isVulnerable

    def is_pausable(self, func:Function) -> bool:
        pausable = False
        if func.is_constructor:
            return True
        for m in func.modifiers:
            if "whenNotPaused" in m.name:
                return True
            if isinstance(m,Function):
                pausable = self._pausable(m)
        if not pausable:
            pausable = self._pausable(func)
        return pausable

    def _pausable(self, func :Function) -> bool:
        for node in func.nodes:
            if node.is_conditional(False):
                conditional_vars = node.state_variables_read
                if (len(conditional_vars) == 1 and
                    str(conditional_vars[0].type) == "bool"):
                    check_state_protection(self, conditional_vars[0])
                    return True
        return False
