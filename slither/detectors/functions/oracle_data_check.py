import re
from logging import Logger
from slither.slither import Slither
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
    "FeedRegistryInterface": "chainlink_data_feed",
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

def identify_oracle_service(self) -> set[str]:
    """
    Identify the oracle services used according to the inherited contract
    :return: oracle service names
    """
    return {SERVICE_MAP[contract.name]
            for contract in self.contracts if contract.name in SERVICE_MAP}

def check_revert_after_payment(self, func: Function) -> None:
    """
    Check the the use of 'revert' or 'require' after payment
    """
    for solCall in func.solidity_calls:
        fname = solCall.function.name
        if "revert" in fname or "require" in fname:
            info: DETECTOR_INFO = [
                "Costs have been incurred, recommend to log the error and return "+
                "instead of aborting execution in ", solCall.node, "\n", 
            ]
            json = self.generate_result(info)
            self.results.append(json)

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

    REDSTONE_APIS = {"getOracleBytesValueFromTxMsg",
                    "getOracleBytesValuesFromTxMsg",
                    "getOracleNumericValueFromTxMsg", 
                    "getOracleNumericValuesFromTxMsg",
                    "getOracleNumericValuesAndTimestampFromTxMsg", 
                    "getOracleNumericValuesWithDuplicatesFromTxMsg"}
    PYTH_FEED_APIS = {"getPriceUnsafe", "getEmaPriceUnsafe",
                    "getPriceNoOlderThan", "getEmaPriceNoOlderThan"}
    PYTH_DEPRECATED_APIS = {"getPrice", "getEmaPrice", "getValidTimePeriod"}
    CHAINLINK_DEPRECATED_APIS = {"getAnswer", "getTimestamp",
                               "latestAnswer", "latestRound", "latestTimestamp"}

    def __init__(self, compilation_unit: SlitherCompilationUnit,
                slither: "Slither", logger: Logger) -> None:
        """
        Clear self.results
        """
        super().__init__(compilation_unit, slither, logger)
        self.results: list[Output] = []

    def _detect(self) -> list[Output]:
        oracleServices = identify_oracle_service(self)
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

    def _check_oracle_response(self, func: Function, responses: set[Variable]) -> None:
        """
        Verify the data check of specified variables in specified function
        """
        checkedRes = set()
        unCheckedRes = set()
        for node in func.nodes:
            if node.is_conditional(False):
                checkedRes.update(node.variables_read)
            # Detect the use of oracle response before check
            else:
                unCheckedRes = {res for res in responses if res not in checkedRes}
                for response in unCheckedRes:
                    usage = [var for var in node.variables_read
                             if is_dependent(var, response, func)]
                    if usage:
                        info: DETECTOR_INFO = ["Oracle response ",response,
                                               " used in ",node," before checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
        # Detect unchecked oracle response
        for res in unCheckedRes:
            info: DETECTOR_INFO = ["Oracle response ", res, " not checked.\n"]
            json = self.generate_result(info)
            self.results.append(json)

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
                check_revert_after_payment(self, func)
                self._check_oracle_response(func, set(func.parameters[1:]))
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
                self._check_oracle_response(func, set(func.parameters))
                check_revert_after_payment(self, func)
        if not fulfillFound:
            self.logger.error("Fail to find the fulfill function!")

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        for func in self.compilation_unit.functions:
            requestCounteer = 0
            for _, highCall in func.high_level_calls:
                if highCall.function_name in self.CHAINLINK_DEPRECATED_APIS:
                    info: DETECTOR_INFO = ["Deprecated function invoked in ",
                                           highCall.node, " Do not use it.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                elif highCall.function_name in ["latestRoundData", "getRoundData"]:
                    requestCounteer += 1
                    if requestCounteer > 1:
                        info: DETECTOR_INFO = ["Sending multiple requests ",
                                               highCall.node, "in a single call.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if highCall.node.variables_written:
                        self._check_feed_response(highCall.node)
                    else:
                        info: DETECTOR_INFO = ["The value in ", highCall.node,
                                               " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)

    def _check_feed_response(self, node:Node) -> None:
        responses = []
        # Extracting the oracle response in the return value
        matched = re.match(r"\s*\(([^)]*?)\)\s*=", str(node.expression))
        if not matched:
            self.logger.error("Fail to extract return value of " +
                                "latestRoundData or getRoundData.")    
        else:
            responses = [v.strip() for v in matched.group(1).split(",")]
            if len(responses) != 5:
                self.logger.error("The return format of " +
                                    "latestRoundData or getRoundData is incorrect.")
        v2, v3, v5 = responses[1], responses[2], responses[4]
        # The value and timestamp should be checked
        if v2 == "None" or v3 == "None":
            info: DETECTOR_INFO = ["value and timestemp of response ",
                                   node," not vaildated.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        # answeredInRound is deprecated and should be None
        if v5 != "None":
            info: DETECTOR_INFO = ["answeredInRound is deprecated.",
                                   node, " Do not use it.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        self._check_oracle_response(node.function, set(node.variables_written))
    ###################################################################################
    ###################################################################################
    # region Chainlink-dataStream
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataStream(self) -> None:
        for func in self.compilation_unit.functions:
            if func.is_implemented and func.name == "performUpkeep":
                vReport = None
                # Extract the validated oracle response
                for _, highCall in func.high_level_calls:
                    if highCall.function_name == "verify":
                        check_revert_after_payment(self, func)
                        if highCall.node.variables_written:
                            vReport = highCall.node.variables_written[0]
                if vReport:
                    decodes = [s for s in func.solidity_calls
                        if (s.function.name == "abi.decode()" and
                            is_dependent(s.node.variables_read[0], vReport, func))
                    ]
                    for decode in decodes:
                        if decode.node.variables_written:
                            self._check_stream_response(
                                decode.node.variables_written[0],func)
                        else:
                            info: DETECTOR_INFO = ["The value of report in ",
                                                decode.node, " not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                else:
                    info: DETECTOR_INFO = ["The oracle response in ",func,
                                           " not verified.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)

    def _check_stream_response(self, finalReport:Variable, func:Function) -> None:
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
            # check use before validation
            else:
                for varRead in node.variables_read:
                    if is_dependent(varRead, finalReport, func):
                        if not timeChecked:
                            info: DETECTOR_INFO = ["validFromTimestamp or expiresAt in ",
                                                   node," not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                        if not valueChecked:
                            info: DETECTOR_INFO = ["price in ", node," not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                        if "4" in str(finalReport.type) and not marketChecked:
                            info: DETECTOR_INFO = ["marketStatus of response in ",
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
                check_revert_after_payment(self, func)
                self._check_tainted_vrf(func, {func.parameters[1]})
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

    def _check_tainted_vrf(self, func:Function, taintPool: set[Variable]) -> None:
        irs = [ir for node in func.nodes for ir in node.irs if self._check_calc(ir)]
        for ir in irs:
            for val in ir.node.variables_read:
                for taint in taintPool:
                    if is_dependent(val, taint, func):
                        taintPool.update(ir.node.variables_written)
                        info: DETECTOR_INFO = ["Random value may be influenced in ",
                                               ir.node," by user-controlled value.\n",]
                        json = self.generate_result(info)
                        self.results.append(json)
            if isinstance(ir, InternalCall) and ir.function:
                self._check_tainted_vrf(ir.function, taintPool)

    def _check_calc(self, ir:Operation) -> bool:
        if isinstance(ir, Binary):
            if ir.type in [
                BinaryType.POWER, BinaryType.CARET, BinaryType.OR,
                BinaryType.MULTIPLICATION, BinaryType.DIVISION, BinaryType.MODULO,
                BinaryType.AND, BinaryType.ADDITION, BinaryType.SUBTRACTION,
                BinaryType.LEFT_SHIFT, BinaryType.RIGHT_SHIFT]:
                if len(ir.node.variables_read) > 1:
                    return True
        return False

    ###################################################################################
    ###################################################################################
    # region Chronicle
    ###################################################################################
    ###################################################################################

    def _detect_chronicle(self) -> None:
        for func in self.compilation_unit.functions:
            requestCounter = 0
            for _, hCall in func.high_level_calls:
                if hCall.function_name in ["read", "readWithAge",
                                           "tryRead", "tryReadWithAge"]:
                    if hCall.node.variables_written:
                        self._check_oracle_response(func, set(hCall.node.variables_written))
                        requestCounter += 1
                        if requestCounter > 1:
                            info: DETECTOR_INFO = ["Sending multiple requests ",
                                                   hCall.node,"in a single call.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                    else:
                        info: DETECTOR_INFO = ["The oracle response in ",
                        hCall.node, " not checked.\n"]
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
                if hCall.function_name in self.PYTH_DEPRECATED_APIS:
                    info: DETECTOR_INFO = ["Deprecated function invoked in ",
                                           hCall.node," Do not use this function.\n"]
                    json = self.generate_result(info)
                    self.results.append(json)
                # check the vaildation of oracle response
                elif hCall.function_name in self.PYTH_FEED_APIS:
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
                        self._check_oracle_response(func, {timestamp, channel})
                    else:
                        info: DETECTOR_INFO = ["timestamp or channel of response in ",
                                               libCall.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                elif libCall.function_name == "parseFeedValueUint64":
                    if libCall.node.variables_written:
                        vals = {val for val in libCall.node.variables_written
                                if str(val.type) == "uint64"}
                        self._check_oracle_response(func, vals)
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
                idChecked = False
                # check tainted vrf
                check_revert_after_payment(self, func)
                self._check_tainted_vrf(func, {func.parameters[2]})
                for node in func.nodes:
                    # check the validation of returned ID
                    if node.is_conditional(False):
                        if func.parameters[0] in node.variables_read:
                            idChecked = True
                    # check use before validation
                    elif not idChecked:
                        uncheckedVars = [var for var in node.variables_read
                                        if is_dependent(var, func.parameters[2], func)]
                        if uncheckedVars:
                            info: DETECTOR_INFO = ["Oracle response used in ", node,
                                                   " before validating request ID.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

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
                if ic.function and ic.function.name in self.REDSTONE_APIS:
                    requestCount += 1
                    if requestCount > 1:
                        info: DETECTOR_INFO = ["Sending multiple requests ",
                                                ic.node, "in a single call.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    if ic.node.variables_written:
                        responses = ic.node.variables_written
                        if ic.function.name == "getOracleNumericValuesAndTimestampFromTxMsg":
                            self._check_oracle_response(func, set(responses))
                        else:
                            # time already checked in the request
                            self._check_oracle_response(func, {responses[0]})
                    else:
                        info: DETECTOR_INFO = ["The value of oracle response in ",
                                                ic.node, " not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
