
from typing import List
from logging import Logger
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
        "_add", "_addBytes", "_addInt", "_addUint", "_addStringArray", "setBuffer",
        "encodeCBOR", "initializeRequest", "initializeRequestForInlineJavaScript",
        "addSecretsReference", "addDONHostedSecrets", "setArgs", "setBytesArgs",
        "_argsToBytes", "parsePayloadHeader", "parseFeedValueUint64"
    }

    INTERNAL_CALLS = {
        "_setChainlinkToken", "_setChainlinkOracle",
        "_buildChainlinkRequest", "_buildOperatorRequest",
        "_sendChainlinkRequest", "_sendChainlinkRequestTo",
        "_sendOperatorRequest", "_sendOperatorRequestTo",
        "_addChainlinkExternalRequest", "_cancelChainlinkRequest",
        "_useChainlinkWithENS", "_updateChainlinkOracleWithENS",
        "_sendRequest", "requestRandomness", "requestRandomnessPayInNative"
    }
    HIGH_LEVEL_CALLS = {
        "getRoundData", "latestRoundData", "verify", "getPriceUnsafe",
        "getEmaPriceUnsafe", "getPriceNoOlderThan", "getEmaPriceNoOlderThan",
        "updatePriceFeeds", "updatePriceFeedsIfNecessary",
        "verifyUpdate", "requestWithCallback"
    }

    chainlink_key_APIs = {"_setChainlinkToken",
                    "_setChainlinkOracle",
                    "_buildChainlinkRequest",
                    "_buildOperatorRequest",
                    "_sendChainlinkRequest",
                    "_sendChainlinkRequestTo",
                    "_sendOperatorRequest",
                    "_sendOperatorRequestTo",
                    "cancelChainlinkRequest"}

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: list[Output] = []

    def _detect(self) -> List[Output]:
        return self.results


    def _detect_chainlink_anyAPI_data(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for internal_call in func.internal_calls:
                    if internal_call.function.name in self.chainlink_key_APIs: # type: ignore
                        # 考虑重写检测权限保护的逻辑
                        if func.is_protected():
                            continue
                        else:
                            info: DETECTOR_INFO = [
                                func,
                                "Any one can invoke this function to operate with the oracle request.\n",
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)

        # 这些internal call所在的函数
        # 确认is_protected的逻辑自己能否接受

        # 这些internal call的关键变量
        # 修改这些变量的函数
