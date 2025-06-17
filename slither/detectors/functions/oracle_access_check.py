
from typing import List
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector, 
    DetectorClassification,
    DETECTOR_INFO,)
from slither.detectors.functions.oracle_data_check import identify_oracle_service

class OracleAccessCheck(AbstractDetector):
    """
    Documentation
    """

    ARGUMENT = 'oracle-access-check'
    HELP = 'Absence of access control in ' \
    'consumer contracts of Chainlink, Chronicle, Pyth, RedStone oracles'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    results = []

    chainlink_key_APIs = {"_setChainlinkToken",
                    "_setChainlinkOracle",
                    "_buildChainlinkRequest",
                    "_buildOperatorRequest",
                    "_sendChainlinkRequest",
                    "_sendChainlinkRequestTo",
                    "_sendOperatorRequest",
                    "_sendOperatorRequestTo",
                    "cancelChainlinkRequest"}
    
    def _detect(self) -> List[Output]:
        # identify the oracle service
        oracle_service = identify_oracle_service(self)
        if oracle_service == "Unknown":
            self.logger.error("No oracle service identified in the detected contract!")
        elif oracle_service == "chainlink_anyApi":
            self._detect_chainlink_anyAPI_data()
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
        return None