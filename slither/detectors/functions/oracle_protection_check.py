
from logging import Logger
from typing import List, Union
from slither.slither import Slither
from slither.utils.output import Output
from slither.core.declarations.contract import Contract
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
    CH_AGGREV3_APIS,CH_STREAM_APIS)

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
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    LIBRARY_CALL = {
        # chainlink-anyAPI/functions/vrf
        "_add", "_addBytes", "_addInt", "_addUint", "_addStringArray",
        "setBuffer", "encodeCBOR", "initializeRequest",
        "initializeRequestForInlineJavaScript", "addSecretsReference",
        "addDONHostedSecrets", "setArgs", "setBytesArgs", "_argsToBytes",
        # pyth-datastream
        "parsePayloadHeader", "parseFeedValueUint64"
    }

    INTERNAL_CALLS = {
        # chainlink-functions/anyAPI
        "_sendRequest", "_setChainlinkToken", "_setChainlinkOracle",
        "_buildChainlinkRequest", "_buildOperatorRequest",
        "_sendChainlinkRequest", "_sendChainlinkRequestTo",
        "_sendOperatorRequest", "_sendOperatorRequestTo",
        "_addChainlinkExternalRequest", "_cancelChainlinkRequest",
        "_useChainlinkWithENS", "_updateChainlinkOracleWithENS",
        # chainlink-vrf
        "requestRandomness", "requestRandomnessPayInNative",
        # redstone
        "getOracleBytesValueFromTxMsg", "getOracleBytesValuesFromTxMsg",
        "getOracleNumericValueFromTxMsg", "getOracleNumericValuesFromTxMsg",
        "getOracleNumericValuesAndTimestampFromTxMsg", "aggregateByteValues",
        "getOracleNumericValuesWithDuplicatesFromTxMsg", "aggregateValues"
    }
    HIGH_LEVEL_CALLS_WITHOUT_ACCESS_CONTROL= CH_AGGREV3_APIS + CH_STREAM_APIS
    HIGH_LEVEL_CALLS = CH_AGGREV3_APIS + CH_STREAM_APIS+[
        # IScribeOptimistic interface already protected
        # Ichronicle interface should be accessed by anyone
        "read", "readWithAge", "tryRead", "tryReadWithAge"
        # pyth-datafeed
        "getPriceUnsafe", "getEmaPriceUnsafe", "getPriceNoOlderThan",
        "getEmaPriceNoOlderThan", "updatePriceFeeds",
        "updatePriceFeedsIfNecessary",
        # pyth-datastream
        "verifyUpdate",
        # pyth-vrf
        "register", "withdraw", "withdrawAsFeeManager", "setFeeManager",
        "request", "requestWithCallback", "reveal", "revealWithCallback",
        "setProviderFee", "setProviderFeeAsFeeManager", "setProviderUri"]

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
                for call in func.library_calls:
                    isVulnerable = self.check_call(call)
                for call in func.internal_calls:
                    isVulnerable = self.check_call(call)
                for _, call in func.high_level_calls:
                    isVulnerable = self.check_call(call)
                    if isVulnerable:
                        self.check_instance(contract)
                if isVulnerable:
                    if not func.is_access_controlled():
                        info: DETECTOR_INFO = [
                            "CWE-284: oracle operation in ", func,
                            " lacks of access control.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
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
        return self.results

    def check_call(self, call:Union[LibraryCall, InternalCall, HighLevelCall]) -> bool:
        isVulnerable = False
        fname = ""
        if isinstance(call.function, Function):
            fname = call.function.name
        if (fname in self.LIBRARY_CALL or
            fname in self.INTERNAL_CALLS or
            fname in self.HIGH_LEVEL_CALLS):
            isVulnerable = True
            for var in call.node.state_variables_read:
                check_state_protection(self, var)
        return isVulnerable

    def check_instance(self, contract:Contract)->None:
        for func in contract.compilation_unit.functions:
            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, TypeConversion) and "IChronicle" in str(ir.expression):
                        if not func.is_access_controlled:
                            info: DETECTOR_INFO = [
                                "CWE-284: interface instantiation in ", func,
                                " lacks of access control.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                        for var in node.state_variables_read:
                            check_state_protection(self, var)

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
                if len(conditional_vars) == 1 and str(conditional_vars[0].type) == "bool":
                    check_state_protection(self, conditional_vars[0])
                    return True
        return False
