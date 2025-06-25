from logging import Logger
from typing import List, Optional
from slither.core.cfg.node import Node, NodeType
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.core.declarations.contract import Contract
from slither.slither import Slither
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.internal_call import InternalCall
from slither.utils.output import Output
from slither.detectors.functions.oracle_data_check import (
    check_revert_after_payment,
    identify_oracle_service)
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO)

class OracleInterfaceCheck(AbstractDetector):
    """
    Detect the misuse of Chainlink oracle APIs
    """
    ARGUMENT = 'oracle-interface-check'
    HELP = 'Incomplete implementation of interface in ' \
    'consumer contracts of Chainlink, Chronicle, Pyth, RedStone oracles'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    CHAINLINK_REQUEST= {"_sendChainlinkRequest",
                        "_sendChainlinkRequestTo",
                        "_sendOperatorRequest",
                        "_sendOperatorRequestTo"}
    DATAFEED_REQUEST = {"latestRoundData", "getRoundData",
                     "getPriceUnsafe", "getEmaPriceUnsafe",
                     "getEmaPriceNoOlderThan", "getPriceNoOlderThan", 
                     "read", "readWithAge", "tryRead", "tryReadWithAge",
                     "getOracleBytesValueFromTxMsg",
                     "getOracleBytesValuesFromTxMsg",
                     "getOracleNumericValueFromTxMsg", 
                     "getOracleNumericValuesFromTxMsg",
                     "getOracleNumericValuesAndTimestampFromTxMsg", 
                     "getOracleNumericValuesWithDuplicatesFromTxMsg"}

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: List[Output] = []

    def _detect(self) -> List[Output]:
        # identify the oracle service
        oracleServices = identify_oracle_service(self)
        if not oracleServices:
            self.logger.error("No oracle service identified in contracts.")
        else:
            for service in oracleServices:
                if service == "chainlink_any_api":
                    self._detect_chainlink_anyAPI()
                elif service == "chainlink_data_feed":
                    self._detect_chainlink_dataFeed()
                elif service == "chainlink_data_stream":
                    self._detect_chainlink_dataStream()
                elif service == "chainlink_vrf":
                    self._detect_chainlink_vrf()
                elif service == "pyth_price_feed":
                    self._detect_pyth_priceFeed()
                elif service == "pyth_price_stream":
                    self._detect_pyth_priceStream()
                elif service == "pyth_vrf":
                    self._detect_pyth_vrf()
                elif service == "redStone":
                    self._detect_redStone()
                elif service == "chronicle":
                    self._detect_chronicle()
        return self.results

    ###################################################################################
    ###################################################################################
    # region Public
    ###################################################################################
    ###################################################################################

    def _check_withdraw(self, contract: Contract, Native: bool, ERC20: bool) -> bool:
        withdrawERC20, withdrawNative = False, False
        for func in contract.functions_declared:
            for _, highCall in func.high_level_calls:
                if highCall.function_name == "transfer":
                    withdrawERC20 = True
            for libCall in func.library_calls:
                if libCall.function_name == "safeTransfer":
                    withdrawERC20 = True
            for call in func.low_level_calls:
                if call.function_name == "call" and "value" in str(call.expression):
                    withdrawNative = True
        if ERC20 and Native:
            return withdrawERC20 and withdrawNative
        if ERC20:
            return withdrawERC20
        if Native:
            return withdrawNative
        return False

    def _request_in_loop(self, node: Optional[Node], counter: int,
                         visited:set[Node]) -> None:
        if node is None or node in visited:
            return
        visited.add(node)

        if node.type == NodeType.STARTLOOP:
            counter += 1
        elif node.type == NodeType.ENDLOOP:
            counter -= 1

        for ir in node.irs:
            if counter > 0:
                if isinstance(ir, HighLevelCall):
                    if ir.function_name in self.DATAFEED_REQUEST:
                        info: DETECTOR_INFO = ["Oracle request in loop in",
                                               node, "which is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                if isinstance(ir, InternalCall) and ir.function:
                    if ir.function.name in self.DATAFEED_REQUEST:
                        info: DETECTOR_INFO = ["Oracle request in loop in",
                                               node, "which is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    else:
                        self._request_in_loop(ir.function.entry_point, counter, visited)
        for son in node.sons:
            self._request_in_loop(son, counter, visited)

    def _check_request_in_loop(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_entry_points:
                if func.is_implemented:
                    self._request_in_loop(func.entry_point, 0, set())

    ###################################################################################
    ###################################################################################
    # region Chainlink-anyAPI
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_anyAPI(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            requestSent, cancled = False, False
            for func in contract.functions_declared:
                for interCall in func.internal_calls:
                    if interCall.function:
                        if interCall.function.name in self.CHAINLINK_REQUEST:
                            requestSent = True
                        if interCall.function.name == "_cancelChainlinkRequest":
                            cancled = True
            if requestSent:
                withdrawed = self._check_withdraw(contract, False, True)
                if not withdrawed:
                    info: DETECTOR_INFO = ["Locked tokens in ", contract,
                                           "Please add withdraw function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                if not cancled:
                    info: DETECTOR_INFO = ["Please add _cancelChainlinkRequest in",
                                           contract," to cancel overtime requests.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        self._check_request_in_loop()
        for func in self.compilation_unit.functions:
            getRoundCalled = False
            for _, highCall in func.high_level_calls:
                if highCall.function_name == "getRoundData":
                    getRoundCalled = True
            if getRoundCalled:
                if not func.view:
                    if len(func.state_variables_written) != 0:
                        info: DETECTOR_INFO = ["State change with getRoundData"
                        " invocation in ",func," could cause high gas cost.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataStream
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataStream(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "verify":
                        self._check_stream_interface(contract)

    def _check_stream_interface(self, contract: Contract) -> None:
        withdrawed = self._check_withdraw(contract, False, True)
        if not withdrawed:
            info: DETECTOR_INFO = ["Locked tokens in ", contract,
                                    "Please add withdraw function.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        for func in contract.functions:
            if func.is_implemented  and func.name == "checkErrorHandler":
                errorCodeChecked = False
                for node in func.nodes:
                    if node.is_conditional(False):
                        if func.parameters[0] in node.variables_read:
                            errorCodeChecked = True
                if not errorCodeChecked:
                    info: DETECTOR_INFO = ["The errorCode of checkErrorHandler in ",
                                           func," should be validated.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################
    def _detect_chainlink_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            payInNative, payInLink, withdrawed = False, False, False
            for func in contract.functions_declared:
                for interCall in func.internal_calls:
                    if hasattr(interCall, "contract_name"):
                        print(interCall.contract_name)
                for libCall in func.library_calls:
                    if libCall.function_name == "_argsToBytes":
                        if "true" in str(libCall.expression):
                            payInNative = True
                        elif "false" in str(libCall.expression):
                            payInLink = True
                        else:
                            payInNative = True
                            payInLink = True
            if payInLink or payInNative:
                if payInLink and payInNative:
                    withdrawed = self._check_withdraw(contract, True, True)
                elif payInNative:
                    withdrawed = self._check_withdraw(contract, True, False)
                elif payInLink:
                    withdrawed = self._check_withdraw(contract, False, True)
                if not withdrawed:
                    info: DETECTOR_INFO = ["Locked Link/Ether token in ", contract,
                                            "Please add withdraw function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chronicle
    ###################################################################################
    ###################################################################################
    def _detect_chronicle(self) -> None:
        self._check_request_in_loop()

    ###################################################################################
    ###################################################################################
    # region Pyth-priceFeed
    ###################################################################################
    ###################################################################################

    def _detect_pyth_priceFeed(self) -> None:
        self._check_request_in_loop()
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _,highCall in func.high_level_calls:
                    if highCall.function_name in ["updatePriceFeedsIfNecessary",
                                                  "updatePriceFeeds", ]:
                        withdrawed = self._check_withdraw(contract, True, False)
                        check_revert_after_payment(self, func)
                        if not withdrawed:
                            info: DETECTOR_INFO = ["Locked token in ",contract,
                                                   "Please add withdraw function.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-lazer
    ###################################################################################
    ###################################################################################

    def _detect_pyth_priceStream(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "verifyUpdate":
                        withdrawed = self._check_withdraw(contract, True, False)
                        check_revert_after_payment(self, func)
                        if not withdrawed:
                            info: DETECTOR_INFO = ["Locked token in ",contract,
                                                   "Please add withdraw function.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "requestWithCallback":
                        withdrawed = self._check_withdraw(contract, True, False)
                        if not withdrawed:
                            info: DETECTOR_INFO = ["Locked token in ",contract,
                                                   "Please add withdraw function.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################

    def _detect_redStone(self) -> None:
        self._check_request_in_loop()
