import re
from logging import Logger
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.slither import Slither
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.library_call import LibraryCall
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO)
from slither.core.cfg.node import Node
from slither.core.variables.variable import Variable
from slither.core.declarations.function import Function
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.slithir.operations.operation import Operation
from slither.slithir.operations.binary import Binary, BinaryType
from slither.slithir.operations.internal_call import InternalCall
from slither.analyses.data_dependency.data_dependency import is_dependent

# Map the inherited contract to the oracle service
# Format: {inherited_contract_name: oracle_service_name, ...}
SERVICE_MAP = {
    "ChainlinkClient": "chainlink_any_api",
    "FunctionsClient": "chainlink_functions",
    "AggregatorV3Interface": "chainlink_data_feed",
    "AccessControlledOffchainAggregator": "chainlink_data_feed",
    "StreamsLookupCompatibleInterface": "chainlink_data_stream",
    "VRFV2PlusClient": "chainlink_vrf",
    "IPyth": "pyth_price_feed",
    "PythLazer": "pyth_price_stream",
    "IEntropyConsumer": "pyth_vrf",
    "RedstoneConsumerBytesBase": "redStone",
    "RedstoneConsumerNumericBase": "redStone",
    "IChronicle": "chronicle",
    "ScribeOptimistic.sol": "chronicle"
}
# high_level_apis
CHRONICLE_FEED_APIS = ["read", "readWithAge", "tryRead", "tryReadWithAge"]

REDSTONE_APIS = {"getOracleBytesValueFromTxMsg",
                "getOracleBytesValuesFromTxMsg",
                "getOracleNumericValueFromTxMsg", 
                "getOracleNumericValuesFromTxMsg",
                "getOracleNumericValuesAndTimestampFromTxMsg", 
                "getOracleNumericValuesWithDuplicatesFromTxMsg"}
PYTH_FEED_APIS = {"getPriceUnsafe", "getEmaPriceUnsafe",
                "getPriceNoOlderThan", "getEmaPriceNoOlderThan"}
PYTH_DEPRECATED_APIS = {"getPrice", "getEmaPrice", "getValidTimePeriod"}

# chainlink-data-feed
# 主要分析AggregatorV3和AccessControlledOffchainAggregator，FeedRegistryInterface已弃用
# 实例化，结果直接返回，highlevel，无需收费
CH_AGGREV3_APIS = ["getRoundData", "latestRoundData"]
CH_DEPR_AGGRE_APIS = ["getAnswer", "getTimestamp", "latestAnswer", "latestTimestamp", "latestRound"]
# chainlink-data-stream
# 回调式，performUpkeep，highlevel，费用由用户授权并支付，但仍建议添加收款
CH_STREAM_APIS = ["verify"]

def get_oracle_services(self) -> set[str]:
    """
    Get oracle services used in the contract according to the inherited contract
    :return: oracle service names
    """
    return {SERVICE_MAP[contract.name]
            for contract in self.contracts if contract.name in SERVICE_MAP}

class OracleDataCheck(AbstractDetector):
    """
    Documentation
    """
    ARGUMENT = 'oracle-data-check'
    HELP = 'Absence of oracle data quality check in ' \
    'consumer contracts of Chainlink, Chronicle, Pyth or RedStone oracles'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: list[Output] = []

    def _detect(self) -> list[Output]:
        oracleServices = get_oracle_services(self)
        if not oracleServices:
            self.logger.error("No oracle service identified. Oracle services " \
            "of Chainlink, Chronicle, Pyth and RedStone are supported.")
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

    def check_ignored_resp(self, hCall:HighLevelCall) -> None:
        if hCall.node.variables_written:
            if hCall.function_name in ["tryRead", "readWithAge"]:
                if len(hCall.node.variables_written) != 2:
                    info: DETECTOR_INFO = ["CWE-20: some values of the response in ",
                                           hCall.node, " should not been ignored.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
            elif hCall.function_name == "tryReadWithAge":
                if len(hCall.node.variables_written) != 3:
                    info: DETECTOR_INFO = ["CWE-20: some values of the response in ",
                                           hCall.node, " should not been ignored.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    def check_oracle_response(self, func: Function, resps: set[Variable]) -> None:
        """
        Verify the value check of specified variables in specified function
        :param func(Function):          the scope of the verification
        :param resps(set[Variable]):    variables should be checked
        """
        checkedResps = set()
        for node in func.nodes:
            if node.is_conditional(False):
                for var in node.variables_read:
                    checkedVars = [resp for resp in resps
                        if resp not in checkedResps and is_dependent(var, resp, func)]
                    checkedResps.update(checkedVars)
            for ir in node.irs:
                # the response may be checked in function invocation
                if (isinstance(ir, (LibraryCall,InternalCall))
                        and isinstance(ir.function, Function)):
                    for var in ir.node.variables_read:
                        possibleCheckedVars = [resp for resp in resps
                            if resp not in checkedResps and is_dependent(var, resp, func)]
                        if possibleCheckedVars:
                            i = self._get_index(str(var.name), str(ir.node.expression))
                            if self._check_param(ir.function, i):
                                checkedResps.update(possibleCheckedVars)
        for var in resps:
            if var not in checkedResps:
                info: DETECTOR_INFO = ["CWE-20: oracle response ", var, " not checked.\n"]
                json = self.generate_result(info)
                self.results.append(json)

    def _get_index(self, target: str, expression: str) -> int:
        """
        Get the index of a specific parameter in a function invocation
        :param target(str):         name of a parameter
        :param expression(str):     string of the invocation expression
        "return:                    index of the parameter
        """
        index = -1
        if target and expression:
            match = re.search(r'\((.*)\)', expression)
            if match:
                args_str = match.group(1)
                args = [arg.strip() for arg in re.split(r',(?![^\(]*\))', args_str)]
                for i, arg in enumerate(args):
                    if target in arg:
                        return i
        self.logger.error(f"Fail to get the index of {target} in {expression}")
        return index

    def _check_param(self, func: Function, index:int) -> bool:
        """
        Verify the value check of specified variable in invoked function
        :param func(Function):  the invoked function
        :param index(int):      the index of the variable in the paremeter list
        :return:                the specified variable is checked in the function
        """
        if index < 0:
            return False
        for node in func.nodes:
            if node.is_conditional(False):
                for var in node.variables_read:
                    if is_dependent(var, func.parameters[index], func):
                        return True
        for call in func.internal_calls + func.library_calls:
            # the parameter may be checked in function invocation
            if isinstance(call.function, Function):
                for var in call.node.variables_read:
                    if is_dependent(var, func.parameters[index], func):
                        i = self._get_index(str(var.name), str(call.node.expression))
                        return self._check_param(call.function, i)
        return False

    def check_tamperred_resp(self, func: FunctionContract, resps: set[Variable]) -> None:
        """
        Verify the oracle value tampered by unprotected parameters or state variables
        :param func(FunctionContract):  the scope of the verification
        :param resps(set[Variable]):    variables should be checked
        """
        for funcion in func.contract_declarer.functions_declared:
            if not funcion.is_implemented:
                continue
            self._check_tamperred_resp(funcion, func.contract_declarer, resps)

    def _check_tamperred_resp(self, func: Function, contract:Contract, resps: set[Variable]) -> None:
        irs = [ir for node in func.nodes for ir in node.irs]
        for ir in irs:
            if (isinstance(ir, (LibraryCall,InternalCall,HighLevelCall))
                    and isinstance(ir.function, Function)):
                self._check_tamperred_resp(ir.function, contract, resps)
            if not self._is_calc(ir) or len(ir.node.variables_read) < 2:
                continue
            respInCalc = False
            paramInCalc = False
            for var in ir.node.variables_read:
                for resp in resps:
                    if is_dependent(var, resp, contract):
                        respInCalc = True
            if respInCalc:
                for var in ir.node.variables_read:
                    for param in func.parameters:
                        if is_dependent(var, param, func):
                            paramInCalc = True
                if paramInCalc:
                    info: DETECTOR_INFO = ["CWE-345: response in ", ir.node,
                                            " may be tampered by parameters.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                if ir.node.state_variables_read:
                    info: DETECTOR_INFO = ["CWE-345: response in ", ir.node,
                        " may be tampered by state variables.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    def _is_calc(self, ir:Operation) -> bool:
        if isinstance(ir, Binary):
            if ir.type in [
                BinaryType.POWER, BinaryType.CARET, BinaryType.OR,
                BinaryType.MULTIPLICATION, BinaryType.DIVISION, BinaryType.MODULO,
                BinaryType.AND, BinaryType.ADDITION, BinaryType.SUBTRACTION,
                BinaryType.LEFT_SHIFT, BinaryType.RIGHT_SHIFT]:
                return True
        return False

    ###################################################################################
    ###################################################################################
    # region Chainlink-anyAPI
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_anyAPI(self) -> None:
        fulfillFound = set()
        fulfillFuncs = self._getFulfill()
        if not fulfillFuncs:
            return
        for func in self.compilation_unit.functions:
            # locate the fulfill function
            if func.name in fulfillFuncs:
                validated, recorded = False, False
                fulfillFound.add(func.name)
                # verify the check the sig and requestID
                for interCall in func.internal_calls:
                    if interCall.function:
                        if interCall.function.name == "_validateChainlinkCallback":
                            validated = True
                    for modififierCall in func.modifiers:
                        if modififierCall.name == "recordChainlinkFulfillment":
                            recorded = True
                if validated and recorded:
                    info: DETECTOR_INFO = [
                        "Use either 'validateChainlinkCallback' or " +
                        "'recordChainlinkFulfillment' in ", func," not both.\n", 
                    ]
                    json = self.generate_result(info)
                    self.results.append(json)
                elif not validated and not recorded:
                    info: DETECTOR_INFO = [
                        "Please use either _validateChainlinkCallback or " +
                        "recordChainlinkFulfillment in ", func, " for validation.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                # check_revert_after_payment(self, func)
                # self.check_oracle_response_check(func, set(func.parameters[1:]))
        missingFulfill = [func for func in fulfillFuncs if func not in fulfillFound]
        if missingFulfill:
            self.logger.error(f"Fail to find callback function: {missingFulfill}.")

    def _getFulfill(self) -> set[str]:
        """
        Get fulfill function selector in request building
        :return: fulfill function names
        """
        fulfillNames = set()
        for func in self.compilation_unit.functions:
            for interCall in func.internal_calls:
                callFunc = interCall.function
                if not callFunc:
                    continue
                type1, type2 =False, False
                if callFunc.name == "_buildOperatorRequest":
                    type1 = True
                elif callFunc.name == "_buildChainlinkRequest":
                    type2 = True
                    if "this" not in str(interCall.node.expression):
                        info: DETECTOR_INFO = [
                            "_buildChainlinkRequest in ", interCall.node, 
                            " sets up other contract as callback, remember to add " +
                            "_addChainlinkExternalRequest in corresponding contract.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                if type1 or type2:
                    fulfillName = self._getSelector(interCall.node, type1, type2)
                    if fulfillName:
                        fulfillNames.add(fulfillName)
        if not fulfillNames:
            self.logger.error("Fail to find fulfill function in contracts.")
        return fulfillNames

    def _getSelector(self, node: Node, fulfilled1: bool, fulfilled2: bool ) -> str:
        """
        Get function name according to the function selector in request building
        :return: fulfill function name
        """
        fulfillName = ""
        # use 'this' in function selector
        match = re.search(r'this\.([^.]+)', str(node.expression))
        if not match:
            # use predefined selector
            if fulfilled1 and node.variables_read[1].source_mapping:
                # function selector is in arg[1]
                match = re.search(r'this\.([^.]+)',
                                    node.variables_read[1].source_mapping.content)
            elif fulfilled2 and node.variables_read[2].source_mapping:
                # function selector is in arg[2]
                match = re.search(r'this\.([^.]+)',
                                    node.variables_read[2].source_mapping.content)
        if match:
            fulfillName = match.group(1)
        else:
            self.logger.error("Fail to find callback selector in request building!")
        return fulfillName
    ###################################################################################
    ###################################################################################
    # region Chainlink-functions
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_functions(self) -> None:
        fulfillFound = False
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == "fulfillRequest":
                fulfillFound = True
                # self.check_oracle_response_check(func, set(func.parameters))
                # check_revert_after_payment(self, func)
        if not fulfillFound:
            self.logger.error("Fail to find the fulfill function!")

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                count = 0
                for _, hCall in func.high_level_calls:
                    if hCall.function_name in CH_DEPR_AGGRE_APIS:
                        count += 1
                        info: DETECTOR_INFO = ["CWE-477: deprecated function invoked in ",
                            hCall.node, " Do not use it.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if hCall.function_name in CH_AGGREV3_APIS:
                        count += 1
                        if hCall.node.variables_written:
                            self._check_chainlink_round_data(hCall.node)
                            self.check_tamperred_resp(func, set(hCall.node.variables_written))
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", hCall.node,
                                " not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                    if count > 1:
                        info: DETECTOR_INFO = ["CWE-400: Sending multiple requests in",
                            hCall.node , " It is not recommended.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

    def _check_chainlink_round_data(self, node:Node) -> None:
        responses = []
        # Extracting the data fields in the round response
        matched = re.match(r"\s*\(([^)]*?)\)\s*=", str(node.expression))
        if not matched:
            self.logger.error("Fail to extract data fields of round request.")
        else:
            responses = [v.strip() for v in matched.group(1).split(",")]
            if len(responses) != 5:
                self.logger.error("The data fields of round response is incorrect.")
        v2, v3, v5 = responses[1], responses[2], responses[4]
        # The data field of answer and startedAt should be checked
        if v2 == "None" or v3 == "None":
            info: DETECTOR_INFO = ["CWE-20: answer and startedAt of response in ",
                node," not vaildated.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        # answeredInRound is deprecated and should be None
        if v5 != "None":
            info: DETECTOR_INFO = ["CWE-20: answeredInRound is deprecated but used in ",
                node, " Do not use it.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        self.check_oracle_response(node.function, set(node.variables_written))
    ###################################################################################
    ###################################################################################
    # region Chainlink-dataStream
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataStream(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_implemented and func.name == "performUpkeep":
                    vReport = None
                    # Extract the validated oracle response
                    for _, highCall in func.high_level_calls:
                        if highCall.function_name in CH_STREAM_APIS:
                            if highCall.node.variables_written:
                                vReport = highCall.node.variables_written[0]
                            else:
                                info: DETECTOR_INFO = ["CWE-252: the verified value in ",
                                    highCall.node, " not checked.\n"]
                                json = self.generate_result(info)
                                self.results.append(json)
                    if vReport:
                        decodes = [s for s in func.solidity_calls
                            if (s.function.name == "abi.decode()" and
                                is_dependent(s.node.variables_read[0], vReport, func))]
                        for decode in decodes:
                            if decode.node.variables_written:
                                self.check_tamperred_resp(func, {decode.node.variables_written[0]})
                                self._check_chainlink_stream_data(func,
                                    decode.node.variables_written[0])
                            else:
                                self.results.append(json)
                                info: DETECTOR_INFO = ["CWE-252: the decoded value in ",
                                    decode.node, " not checked.\n"]
                                json = self.generate_result(info)
                                self.results.append(json)
                    else:
                        info: DETECTOR_INFO = ["CWE-345: oracle response in ",
                            func, " not verified.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

    def _check_chainlink_stream_data(self, func:Function, finalReport:Variable) -> None:
        valueChecked, timeChecked, marketChecked = False, False, False
        for node in func.nodes:
            # check the validation of returned value
            if node.is_conditional(False):
                expr = str(node.expression)
                if finalReport in node.variables_read:
                    if "validFromTimestamp" in expr or "expiresAt" in expr:
                        timeChecked = True
                    if "price" in expr:
                        valueChecked = True
                    if "marketStatus" in expr:
                        marketChecked = True
            if not timeChecked:
                info: DETECTOR_INFO = ["CWE-252: validFromTimestamp or expiresAt in ",
                    node," not checked.\n"]
                json = self.generate_result(info)
                self.results.append(json)
            if not valueChecked:
                info: DETECTOR_INFO = ["CWE-252: price in ", node," not checked.\n"]
                json = self.generate_result(info)
                self.results.append(json)
            if "4" in str(finalReport.type) and not marketChecked:
                info: DETECTOR_INFO = ["CWE-252: marketStatus of response in ",
                    node, " not checked.\n"]
                json = self.generate_result(info)
                self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################
    def _detect_chainlink_vrf(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == "fulfillRandomWords":
                idChecked = False
                # check tainted vrf
                # check_revert_after_payment(self, func)
                # self._check_tainted_vrf(func, {func.parameters[1]})
                for node in func.nodes:
                    # check the validation of returned ID
                    if node.is_conditional(False):
                        if func.parameters[0] in node.variables_read:
                            idChecked = True
                    # check use before validation
                    elif not idChecked:
                        uncheckedVars = [var for var in node.variables_read
                                        if is_dependent(var, func.parameters[1], func)]
                        if uncheckedVars:
                            info: DETECTOR_INFO = ["Oracle response used in ", node,
                                                   " before validating request ID.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-priceFeed
    ###################################################################################
    ###################################################################################
    def _detect_pyth_priceFeed(self) -> None:
        for func in self.compilation_unit.functions:
            requestCounter = 0
            for _, hCall in func.high_level_calls:
                if hCall.function_name in PYTH_DEPRECATED_APIS:
                    info: DETECTOR_INFO = ["Deprecated function invoked in ",
                                           hCall.node," Do not use this function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                # check the vaildation of oracle response
                elif hCall.function_name in PYTH_FEED_APIS:
                    unsafe = False
                    if hCall.function_name in ["getEmaPriceUnsafe", "getPriceUnsafe"]:
                        # the timestamp of the response need to be checked
                        unsafe = True
                    if not hCall.node.variables_written:
                        info: DETECTOR_INFO = ["The oracle response in ",
                                               hCall.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    else:
                        self._check_pythFeed(hCall.node.variables_written[0],
                                             unsafe, func)
                        requestCounter += 1
                        if requestCounter > 1:
                            info: DETECTOR_INFO = ["Sending multiple requests ",
                                                   hCall.node,"in a single call.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    def _check_pythFeed(self, response:Variable, unsafe:bool, func:Function) -> None:
        # check the validation of oracle response
        valueChecked, timeChecked = False, False
        for node in func.nodes:
            if node.is_conditional(False) and response in node.variables_read:
                if ".price" in str(node.expression):
                    valueChecked = True
                if ".publishTime" in str(node.expression):
                    timeChecked = True
            elif not valueChecked:
                for varRead in node.variables_read:
                    if is_dependent(varRead, response, func):
                        info: DETECTOR_INFO = ["price of response",node,
                                               " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                        if unsafe and not timeChecked:
                            info: DETECTOR_INFO = ["publishTime of response ",node,
                                                   " not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-lazer
    ###################################################################################
    ###################################################################################

    def _detect_pyth_priceStream(self) -> None:
        for func in self.compilation_unit.functions:
            for libCall in func.library_calls:
                if libCall.function_name == "parsePayloadHeader":
                    verified = False
                    for _, highCall in func.high_level_calls:
                        if highCall.function_name == "verifyUpdate":
                            verified = True
                    if not verified:
                        info: DETECTOR_INFO = ["The oracle response in ",func,
                                               " not verified.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    # Extracting the result in payload
                    timestamp, channel = None, None
                    for val in libCall.node.variables_written:
                        if str(val.type) == "uint64":
                            timestamp = val
                        elif str(val.type) == "PythLazerLib.Channel":
                            channel = val
                    if timestamp and channel:
                        ...
                        # self.check_oracle_response_check(func, {timestamp, channel})
                    else:
                        info: DETECTOR_INFO = ["timestamp or channel of response in ",
                                               libCall.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                elif libCall.function_name == "parseFeedValueUint64":
                    if libCall.node.variables_written:
                        vals = {val for val in libCall.node.variables_written
                                if str(val.type) == "uint64"}
                        # self.check_oracle_response_check(func, vals)
                    else:
                        info: DETECTOR_INFO = ["The value of oracle response in ",
                                               libCall.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)


    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == "entropyCallback":
                ...
                # check_revert_after_payment(self, func)
                # self._check_tainted_vrf(func, {func.parameters[2]})
                # self.check_oracle_response_check(func, {func.parameters[0]})

    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################
    def _detect_redStone(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_virtual:
                continue
            requestCount = 0
            for ic in func.internal_calls:
                if ic.function and ic.function.name in REDSTONE_APIS:
                    requestCount += 1
                    if requestCount > 1:
                        info: DETECTOR_INFO = ["CWE-400: multiple requests sent in ",
                                                ic.node, " in a single transaction.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    stateVar = ic.node.state_variables_read
                    if stateVar:
                        ...
                        # self.check_state_protected(stateVar[0])
                    if ic.node.variables_written:
                        responses = ic.node.variables_written
                        if ic.function.name == "getOracleNumericValuesAndTimestampFromTxMsg":
                            ...
                            # self.check_oracle_response_check(func, set(responses))
                        else:
                            ...
                            # time already checked in the request
                            # self.check_oracle_response_check(func, {responses[0]})
                    else:
                        info: DETECTOR_INFO = ["CWE-20: oracle response in ",
                                                ic.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chronicle
    ###################################################################################
    ###################################################################################

    def _detect_chronicle(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, hCall in func.high_level_calls:
                    if hCall.function_name in CHRONICLE_FEED_APIS:
                        # these apis do not return timestamp
                        if hCall.function_name in ["read", "tryRead"]:
                            info: DETECTOR_INFO = ["CWE-20: time of the response in ",
                                                    hCall.node, " should be checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                        # the response may be returned directly
                        if hCall.node.variables_written:
                            # check whether some values of response are ignored
                            self.check_ignored_resp(hCall)
                            # verify the data check
                            self.check_oracle_response(func, set(hCall.node.variables_written))
                            # verify the unprotected tamper
                            self.check_tamperred_resp(func, set(hCall.node.variables_written))
                        else:
                            info: DETECTOR_INFO = ["CWE-20: oracle response returned in ",
                                                    hCall.node, "without check.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
