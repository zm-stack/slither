from logging import Logger
from typing import List, Optional
from slither.core.cfg.node import Node, NodeType
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.core.declarations.contract import Contract
from slither.core.declarations.function import Function
from slither.slither import Slither
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.internal_call import InternalCall
from slither.slithir.operations.library_call import LibraryCall
from slither.slithir.operations.solidity_call import SolidityCall
from slither.utils.output import Output
from slither.detectors.functions.oracle_data_check import (
    CH_DEPR_AGGRE_APIS, CH_FEED_APIS, CH_FUNCTIONS_FULFILL,
    CH_VRF_FULFILL, PYTH_DEPRECATED_APIS, PYTH_FEED_SAFE_APIS,
    PYTH_FEED_UNSAFE_APIS,  PYTH_VRF_FULFILL, CHRONICLE_FEED_APIS,
    REDSTONE_FEED_APIS, get_oracle_services)
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
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    FEED_APIS = (CH_FEED_APIS+PYTH_FEED_SAFE_APIS+PYTH_FEED_UNSAFE_APIS+
                 CHRONICLE_FEED_APIS + REDSTONE_FEED_APIS)

    CHAINLINK_REQUEST= {"_sendChainlinkRequest",
                        "_sendChainlinkRequestTo",
                        "_sendOperatorRequest",
                        "_sendOperatorRequestTo"}

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: List[Output] = []

    def _detect(self) -> List[Output]:
        # identify the oracle service
        oracleServices = get_oracle_services(self)
        if not oracleServices:
            self.logger.error("No oracle service identified in contracts.")
        else:
            for service in oracleServices:
                if service == "chainlink_any_api":
                    self._detect_chainlink_anyAPI()
                elif service == "chainlink_functions":
                    self._detect_chainlink_functions()
                elif service == "chainlink_data_feed":
                    self._detect_chainlink_dataFeed()
                elif service == "chainlink_data_stream":
                    self._detect_chainlink_dataStream()
                elif service == "chainlink_vrf_Sub":
                    self._detect_chainlink_vrf_Sub()
                elif service == "chainlink_vrf_DF":
                    self._detect_chainlink_vrf_DF()
                elif service == "pyth_price_feed":
                    self._detect_pyth_priceFeed()
                elif service == "pyth_vrf":
                    self._detect_pyth_vrf()
                elif service == "redStone":
                    self._detect_redStone()
                elif service == "chronicle":
                    self._detect_chronicle()
        return self.results

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        self.check_multi_request()
        self.check_depracated_apis()
        self.check_request_in_loop()
        for func in self.compilation_unit.functions:
            getRoundCalled = False
            for _, highCall in func.high_level_calls:
                if highCall.function_name == "getRoundData":
                    getRoundCalled = True
            if getRoundCalled:
                if not func.view and not func.pure:
                    info: DETECTOR_INFO = ["CWE-400: the function invokes getRoundData"
                        " shoulud be view or pure. Since state change with getRoundData in ",
                        func, " could cause high gas cost.\n"]
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
                if func.is_implemented and func.name == "checkErrorHandler":
                    errorCodeChecked = False
                    for node in func.nodes:
                        if (node.is_conditional(False) and
                            func.parameters[0] in node.variables_read):
                            errorCodeChecked = True
                    if not errorCodeChecked:
                        info: DETECTOR_INFO = ["CWE-703: errorCode of"
                        " checkErrorHandler ", func," should be checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

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
                withdrawed = self.check_withdraw(contract, False, True)
                if not withdrawed:
                    info: DETECTOR_INFO = ["CWE-400: locked tokens in ", contract,
                                           " Please add withdraw function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                if not cancled:
                    info: DETECTOR_INFO = ["CWE-703: add _cancelChainlinkRequest in",
                                           contract," to cancel overtime requests.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-function
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_functions(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == CH_FUNCTIONS_FULFILL:
                self.check_revert_after_payment(func)
            for inCall in func.internal_calls:
                f = inCall.function
                if f and f.name == CH_FUNCTIONS_FULFILL and func.name != "handleOracleFulfillment":
                    info: DETECTOR_INFO = ["CWE-703: only oracle service can invoke fulfillRequest",
                        inCall.node ," please remove this call.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_vrf_DF(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            payInNative, payInLink, withdrawed = False, False, False
            for func in contract.functions_declared:
                if func.is_implemented and func.name == CH_VRF_FULFILL:
                    self.check_revert_after_payment(func)
                for inCall in func.internal_calls:
                    if not inCall.function:
                        continue
                    fname = inCall.function.name
                    if fname == CH_VRF_FULFILL and func.name != "rawFulfillRandomWords":
                        info: DETECTOR_INFO = ["CWE-703: only oracle can invoke fulfillRequest",
                            inCall.node ," please remove this call.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    elif fname == "requestRandomness":
                        payInLink = True
                    elif fname == "requestRandomnessPayInNative":
                        payInNative = True
                    if payInLink or payInNative:
                        withdrawed = self.check_withdraw(contract, payInNative, payInLink)
                        if not withdrawed:
                            info: DETECTOR_INFO = ["CWE-400: locked tokens in ", contract,
                                                " Please add withdraw function.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    def _detect_chainlink_vrf_Sub(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == CH_VRF_FULFILL:
                self.check_revert_after_payment(func)
            for inCall in func.internal_calls:
                if not inCall.function:
                    continue
                fname = inCall.function.name
                if fname == CH_VRF_FULFILL and func.name != "rawFulfillRandomWords":
                    info: DETECTOR_INFO = ["CWE-703: only oracle can invoke fulfillRequest",
                        inCall.node ," please remove this call.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-priceFeed
    ###################################################################################
    ###################################################################################

    def _detect_pyth_priceFeed(self) -> None:
        self.check_multi_request()
        self.check_request_in_loop()
        self.check_depracated_apis()

    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == PYTH_VRF_FULFILL:
                self.check_revert_after_payment(func)
            for inCall in func.internal_calls:
                if not inCall.function:
                    continue
                fname = inCall.function.name
                if fname == PYTH_VRF_FULFILL and func.name != "_entropyCallback":
                    info: DETECTOR_INFO = ["CWE-703: only oracle can invoke entropyCallback ",
                        inCall.node ," please remove this call.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)


    ###################################################################################
    ###################################################################################
    # region Chronicle
    ###################################################################################
    ###################################################################################

    def _detect_chronicle(self) -> None:
        self.check_request_in_loop()
        self.check_multi_request()

    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################

    def _detect_redStone(self) -> None:
        self.check_request_in_loop()
        self.check_multi_request()

    ###################################################################################
    ###################################################################################
    # region Public
    ###################################################################################
    ###################################################################################

    def check_multi_request(self) -> None:
        """
        Check whether multiple oracle requests are sent in one transaction
        """
        for func in self.compilation_unit.functions:
            self._check_multi_request(func, 0)

    def _check_multi_request(self, func:Function, counter:int, visited=None) -> None:
        if visited is None:
            visited = set()
        if func in visited:
            return
        visited.add(func)
        for _, hCall in func.high_level_calls:
            if hCall.function_name in self.FEED_APIS:
                counter += 1
                if counter > 1:
                    info: DETECTOR_INFO = ["CWE-400: multiple requests sent in ",
                        hCall.node, " which is not recommended.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
        for iCall in func.internal_calls:
            if isinstance(iCall.function, Function):
                if iCall.function.name in self.FEED_APIS:
                    counter += 1
                    if counter > 1:
                        info: DETECTOR_INFO = ["CWE-400: multiple requests sent in ",
                            iCall.node, " which is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                else:
                    self._check_multi_request(iCall.function, counter, visited)

    def check_depracated_apis(self) ->None:
        """
        Check the use of depracated APIs
        """
        for func in self.compilation_unit.functions:
            for _, highCall in func.high_level_calls:
                if highCall.function_name in CH_DEPR_AGGRE_APIS+PYTH_DEPRECATED_APIS:
                    info: DETECTOR_INFO = ["Deprecated function invoked in ",
                                           highCall.node," Do not use this function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    def check_request_in_loop(self) -> None:
        """
        Check whether the oracle requests are sent in a loop
        """
        for func in self.compilation_unit.functions:
            if func.is_implemented:
                self._check_request_in_loop(func.entry_point, 0, set())

    def _check_request_in_loop(self, node: Optional[Node], counter: int,
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
                    if ir.function_name in self.FEED_APIS:
                        info: DETECTOR_INFO = ["CWE-400: oracle request in loop in ",
                            node, " which is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                if isinstance(ir, InternalCall) and ir.function:
                    if ir.function.name in self.FEED_APIS:
                        info: DETECTOR_INFO = ["CWE-400: oracle request in loop in ",
                            node, " which is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    else:
                        self._check_request_in_loop(ir.function.entry_point, counter, visited)
        for son in node.sons:
            self._check_request_in_loop(son, counter, visited)

    def check_withdraw(self, contract: Contract, Native: bool, ERC20: bool) -> bool:
        withdrawERC20, withdrawNative = False, False
        for func in contract.functions_declared:
            withdrawed = False
            for _, highCall in func.high_level_calls:
                if highCall.function_name == "transfer":
                    withdrawed = True
                    withdrawERC20 = True
            for libCall in func.library_calls:
                if libCall.function_name == "safeTransfer":
                    withdrawed = True
                    withdrawERC20 = True
            for call in func.low_level_calls:
                if call.function_name == "call" and "value" in str(call.expression):
                    withdrawed = True
                    withdrawNative = True
            if withdrawed and not func.is_access_controlled():
                info: DETECTOR_INFO = ["CWE-284: withdraw function in ",
                    func, " is not protrcted.\n"]
                json = self.generate_result(info)
                self.results.append(json)
        if ERC20 and Native:
            return withdrawERC20 and withdrawNative
        if ERC20:
            return withdrawERC20
        if Native:
            return withdrawNative
        return False

    def check_revert_after_payment(self, func:Function, visited=None) -> None:
        """
        Check the the use of 'revert' or 'require' after oracle requst payment
        """
        if visited is None:
            visited = set()
        if func in visited:
            return
        visited.add(func)
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, SolidityCall):
                    fname = ir.function.name
                    if "revert" in fname or "require" in fname:
                        info: DETECTOR_INFO = [
                            "CWE-703: revert in ", node, " Costs have been incurred,",
                            " recommend to log the error instead of aborting execution\n", 
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
                if (isinstance(ir, (LibraryCall, InternalCall, HighLevelCall))
                    and isinstance(ir.function, Function)):
                    self.check_revert_after_payment(ir.function, visited)
