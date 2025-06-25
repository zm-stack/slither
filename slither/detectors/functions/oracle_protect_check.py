
from typing import List
from logging import Logger
from slither.core.declarations.function import Function
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.slither import Slither
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,)

class OracleProtectCheck(AbstractDetector):
    """
    Documentation
    """

    ARGUMENT = 'oracle-protect-check'
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
    HIGH_LEVEL_CALLS = {
        # chainlink-datafeed/datastream
        "getRoundData", "latestRoundData", "verify",
        # chronicle
        "read", "readWithAge", "tryRead", "tryReadWithAge",
        # pyth-datafeed
        "getPriceUnsafe", "getEmaPriceUnsafe", "getPriceNoOlderThan",
        "getEmaPriceNoOlderThan", "updatePriceFeeds",
        "updatePriceFeedsIfNecessary",
        # pyth-datastream/vrf
        "verifyUpdate", "register", "withdraw", "withdrawAsFeeManager",
        "request", "requestWithCallback", "reveal", "revealWithCallback",
        "setProviderFee", "setProviderFeeAsFeeManager", "setProviderUri",
        "setFeeManager"
    }

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
                for libCall in func.library_calls:
                    if libCall.function_name in self.LIBRARY_CALL:
                        print(libCall.function_name)
                        isVulnerable = True
                for inCall in func.internal_calls:
                    if inCall.function and inCall.function.name in self.INTERNAL_CALLS:
                        print(inCall.function.name)
                        if func.is_protected:
                            print("protect")
                        isVulnerable = True
                for _, highCall in func.high_level_calls:
                    if highCall.function_name in self.HIGH_LEVEL_CALLS:
                        print(highCall.function_name)
                        isVulnerable = True
                if isVulnerable:
                    if not self.is_access_controlled(func):
                        info: DETECTOR_INFO = [
                            "Oracle request in ", func,
                            "lacks of access control.\n"
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if not self.is_pausable(func):
                        info: DETECTOR_INFO = [
                            "Oracle request in ", func,
                            "is not pausable.\n"
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if not contract.is_upgradeable:
                        info: DETECTOR_INFO = [
                            "Oracle consumer contract ", contract,
                            "is not upgradeable.\n"
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
        return self.results

    def is_pausable(self, func:Function) -> bool:
        if func.is_constructor:
            return True
        for m in func.modifiers:
            if "whenNotPaused" in m.name:
                return True
        for solCall in func.solidity_calls:
            fname = solCall.function.name
            if "revert" in fname or "require" in fname:
                conditional_vars = solCall.node.state_variables_read
                if len(conditional_vars) == 1 and conditional_vars[0].type == "bool":
                    return True
        return False

    def is_access_controlled(self, func:Function) -> bool:
        if func.is_constructor:
            return True
        for m in func.modifiers:
            if "onlyOwner" in m.name:
                return True
        conditional_vars = func.all_conditional_solidity_variables_read(include_loop=False)
        args_vars = func.all_solidity_variables_used_as_args()
        if SolidityVariableComposed("msg.sender") in conditional_vars + args_vars:
            return True
        return False
