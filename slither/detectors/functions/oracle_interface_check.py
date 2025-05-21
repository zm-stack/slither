from logging import Logger
from typing import List, Optional

from attr import s
from slither.core.cfg.node import Node, NodeType
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.core.declarations.contract import Contract
from slither.slither import Slither
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.internal_call import InternalCall
from slither.utils.output import Output
from slither.detectors.functions.oracle_data_check import identify_oracle_service_via_import
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

    transfers  =   {"transfer", "transferFrom"}
    chainlinkSendRequest= {"_sendChainlinkRequest",
                            "_sendChainlinkRequestTo",
                            "_sendOperatorRequest",
                            "_sendOperatorRequestTo"}
    dataFeedRequest = {"latestRoundData", "getRoundData", 
                     "getEmaPriceNoOlderThan", "getPriceNoOlderThan", 
                     "getEmaPriceUnsafe", "getPriceUnsafe"}
    
    def __init__(self, compilation_unit: SlitherCompilationUnit, 
                slither: "Slither", logger: Logger) -> None:
        super().__init__(compilation_unit, slither, logger)
        self.results: List[Output] = []

    def _detect(self) -> List[Output]:
        # identify the oracle service
        oracleServices = identify_oracle_service_via_import(self)
        if not oracleServices:
            self.logger.error("No oracle service identified in contracts.")
        else:
            for service in oracleServices:
                if service == "chainlink_any_api":
                    self._detect_chainlink_anyAPI_data()
                elif service == "chainlink_data_feed":
                    self._detect_chainlink_dataFeed()
                elif service == "chainlink_data_stream":
                    self._detect_chainlink_dataStream()
                elif service == "chainlink_vrf":
                    self._detect_chainlink_vrf()
                elif service == "pyth_price_feed":
                    self._detect_pyth_priceFeed()
                elif service == "pyth_vrf":
                    self._detect_pyth_vrf()
        return self.results
    
    ###################################################################################
    ###################################################################################
    # region Public
    ###################################################################################
    ###################################################################################
    def _check_withdraw(self, contract: Contract, checkNative: bool, checkERC20: bool) -> bool:
        withdrawERC20, withdrawNative = False, False
        for func in contract.functions_declared:
            if checkERC20:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "transfer":
                        withdrawERC20 = True
                for libCall in func.library_calls:
                    if libCall.function_name == "safeTransfer":
                        withdrawERC20 = True
            if checkNative:
                for lowCall in func.low_level_calls:
                    if lowCall.function_name == "call":
                        if "value" in str(lowCall.expression):
                            withdrawNative = True
        if checkERC20 and checkNative:
            return withdrawERC20 and withdrawNative
        elif checkERC20:
            return withdrawERC20
        elif checkNative:
            return withdrawNative
        else:
            return False
        
    def _request_in_loop(self, node: Optional[Node], counter: int, visited:set[Node]) -> None:
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
                    if ir.function_name in self.dataFeedRequest:
                        info: DETECTOR_INFO = [
                            node,
                            "Oracle request in loop is not recommended.\n",
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
                if isinstance(ir, InternalCall) and ir.function:
                    self._request_in_loop(ir.function.entry_point, counter, visited)
        for son in node.sons:
            self._request_in_loop(son, counter, visited)
    
    def _check_request_in_loop(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_entry_points:
                if func._is_implemented:
                    self._request_in_loop(func.entry_point, 0, set())
    ###################################################################################
    ###################################################################################
    # region Chainlink-anyAPI
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_anyAPI_data(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            cancled = False
            vulnerContract = None
            for func in contract.functions_declared:
                for internal_call in func.internal_calls:
                    if internal_call.function:
                        if internal_call.function_name in self.chainlinkSendRequest:
                            vulnerContract = contract
                        if internal_call.function_name == "_cancelChainlinkRequest":
                            cancled = True
            if vulnerContract:
                withdrawed = self._check_withdraw(vulnerContract, False, True)
                if not withdrawed:
                    info: DETECTOR_INFO = [
                        contract,
                        "Locked tokens. Please add 'withdraw' function to withdraw Link tokens.\n",
                    ]
                    json = self.generate_result(info)
                    self.results.append(json)
                if not cancled:
                    info: DETECTOR_INFO = [
                        vulnerContract,
                        "Recommend to add 'cancelChainlinkRequest' to cancel overtime requests.\n",
                    ]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        self._check_request_in_loop()
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                getRoundCalled = False
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "getRoundData":
                        getRoundCalled = True
                if getRoundCalled:
                    if not func.view:
                        if len(func.state_variables_written) != 0:
                            info: DETECTOR_INFO = [
                                func,
                                "State change in the same function with 'getRoundData' could " +
                                    "cause very high gas prices.\n"
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataStream
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataStream(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            mainContract = None
            for func in contract.functions_declared:
                for solCall in func.solidity_calls:
                    if "revert" in solCall.function.name and "StreamsLookup" in solCall.function.name:
                        mainContract = contract
            if mainContract:
                verified = False
                withdrawed = False
                for func in mainContract.functions:
                    if func.is_override:
                        if func.name == "checkErrorHandler":
                            errorCodeChecked = False
                            for node in func.nodes:
                                if node.is_conditional(False):
                                    if func.parameters[0] in node.variables_read:
                                        errorCodeChecked = True
                            if not errorCodeChecked:
                                info: DETECTOR_INFO = [
                                    func,
                                    "The 'errorCode' of 'checkErrorHandler' should be validated.\n"
                                ]
                                json = self.generate_result(info)
                                self.results.append(json)
                        elif func.name == "performUpkeep":
                            for _, highCall in func.high_level_calls:
                                if highCall.function_name == "verify":
                                    verified = True
                            if not verified:
                                info: DETECTOR_INFO = [
                                    func,
                                    "The calldata should be verified.\n"
                                ]
                                json = self.generate_result(info)
                                self.results.append(json)
                if verified:
                    withdrawed = self._check_withdraw(mainContract, False, True)
                    if not withdrawed:
                        info: DETECTOR_INFO = [
                            mainContract,
                            "Locked tokens. Please add 'withdraw' function to withdraw your balance.\n",
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################
    def _detect_chainlink_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            mainContract = None
            payInNative, payInLink, payInEither, withdrawed = False, False, False, False
            for func in contract.functions_declared:
                for libCall in func.library_calls:
                    if libCall.function_name == "_argsToBytes":
                        mainContract = contract
                        if "nativePayment" in str(libCall.expression):
                            if "true" in str(libCall.expression):
                                payInNative = True
                            elif "false" in str(libCall.expression):
                                payInLink = True
                            else:
                                payInEither = True
            if mainContract:
                if payInLink:
                    withdrawed = self._check_withdraw(mainContract, False, True)
                elif payInNative:
                    withdrawed = self._check_withdraw(mainContract, True, False)
                elif payInEither:
                    withdrawed = self._check_withdraw(mainContract, True, True)
                else:
                    self.logger.error("Fail to find 'nativePayment' config in '_argsToBytes'!")
                if not withdrawed:
                    info: DETECTOR_INFO = [
                        mainContract,
                        "Locked tokens. Please add 'withdraw' function to withdraw your balance.\n"
                    ]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chronicle
    ###################################################################################
    ###################################################################################

    ###################################################################################
    ###################################################################################
    # region Pyth-priceFeed
    ###################################################################################
    ###################################################################################

    def _detect_pyth_priceFeed(self) -> None:
        self._check_request_in_loop()
        for contract in self.compilation_unit.contracts_derived:
            vulnerContract = None
            for func in contract.functions_declared:
                for _,highCall in func.high_level_calls:
                    if highCall.function_name in ["updatePriceFeedsIfNecessary", "updatePriceFeeds"]:
                            vulnerContract = contract
            if vulnerContract:
                withdrawed = self._check_withdraw(vulnerContract, True, False)
                if not withdrawed:
                    info: DETECTOR_INFO = [
                        contract,
                        "Locked tokens. Please add 'withdraw' function to withdraw your balance.\n",
                    ]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-lazer
    ###################################################################################
    ###################################################################################

    def _detect_pyth_lazer(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "verifyUpdate":
                        withdrawed = self._check_withdraw(contract, True, False)
                        if not withdrawed:
                            info: DETECTOR_INFO = [
                                contract,
                                "Locked tokens. Please add 'withdraw' function to withdraw your balance.\n",
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            mainContract = None
            withdrawed = False
            for func in contract.functions_declared:
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "requestWithCallback":
                        withdrawed = self._check_withdraw(contract, True, False)
                        if not withdrawed:
                            info: DETECTOR_INFO = [
                                contract,
                                "Locked tokens. Please add 'withdraw' function to withdraw your balance.\n"
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################