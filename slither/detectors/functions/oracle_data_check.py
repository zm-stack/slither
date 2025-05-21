import re
from logging import Logger
from typing import List, Sequence, Set
from slither.slither import Slither
from slither.slithir.operations.internal_call import InternalCall
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector, 
    DetectorClassification,
    DETECTOR_INFO)
from slither.core.variables.variable import Variable
from slither.core.declarations.function import Function
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.slithir.operations import SolidityCall
from slither.slithir.operations.binary import Binary, BinaryType
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.analyses.data_dependency.data_dependency import is_dependent

oracle_api_map = {
    "ChainlinkClient": "chainlink_any_api",
    "FunctionsClient": "chainlink_functions",
    "AggregatorV3Interface": "chainlink_data_feed",
    "FeedRegistryInterface": "chainlink_data_feed",
    "AccessControlledOffchainAggregator": "chainlink_data_feed",
    "StreamsLookupCompatibleInterface": "chainlink_data_stream",
    "VRFV2PlusClient": "chainlink_vrf",
    "IPyth": "pyth_price_feed",
    "PythLazer": "pyth_lazer",
    "IEntropyConsumer": "pyth_vrf",
    "RedstoneConsumerBase": "redStone",
}

def identify_oracle_service_via_import(self) -> Set[str]:
    """
    Identify the oracle service used according to the import
    :return: oracle service type
    """
    serviceUsed = set()
    for contract in self.contracts:
        if contract.name in oracle_api_map:
            serviceUsed.add(oracle_api_map[contract.name])
    return serviceUsed

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

    PythFeedAPIs = {"getEmaPriceNoOlderThan", "getPriceNoOlderThan", 
                    "getEmaPriceUnsafe", "getPriceUnsafe"}
    deprecatedPythAPIs = {"getEmaPrice", "getPrice", "getValidTimePeriod"}
    deprecatedChainlinkAPIs = {"getAnswer", "getTimestamp", 
                               "latestAnswer", "latestRound", "latestTimestamp"}

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
                elif service == "chainlink_functions":
                    self._detect_chainlink_functions_data()
                elif service == "chainlink_data_feed":
                    self._detect_chainlink_dataFeed()
                elif service == "chainlink_data_stream":
                    self._detect_chainlink_dataStream()
                elif service == "chainlink_vrf":
                    self._detect_chainlink_vrf()
                elif service == "pyth_price_feed":
                    self._detect_pyth_priceFeed()
                elif service == "pyth_lazer":
                    self._detect_pyth_lazer()
                elif service == "pyth_vrf":
                    self._detect_pyth_vrf()
                elif service == "redStone":
                    self._detect_redStone()
        return self.results

    ###################################################################################
    ###################################################################################
    # region Public
    ###################################################################################
    ###################################################################################

    def _check_oracle_response(self, func: Function, vals: Sequence[Variable]) -> None:
        """
        Check the validation of specified variables in specified function
        :return: None
        """
        # check the validation of fulfill parameters
        checkedVals = set()
        for node in func.nodes:
            if node.is_conditional(False):
                for val in vals:
                    if val in node.variables_read:
                        checkedVals.add(val)
            # check use before validation
            else:
                for varRead in node.variables_read:
                    for val in vals:
                        if is_dependent(varRead, val, func) and val not in checkedVals:
                            info: DETECTOR_INFO = [
                                "Oracle response ", val, " in ", node, " used before validated.\n",
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)
        for val in vals:
            if val not in checkedVals:
                info: DETECTOR_INFO = [
                    "Oracle response ", val, " not validated.\n",
                ]
                json = self.generate_result(info)
                self.results.append(json)
    
    def _check_revert_in_fallback(self, func: Function) -> None:
        # check the use to revert or require
        solCalls = func.solidity_calls
        for solCall in solCalls:
            collee = solCall.function.name
            if "revert" in collee or "require" in collee:
                info: DETECTOR_INFO = [
                    "Costs have been incurred, log the error and return "+
                    "instead of ", solCall.node, " aborting execution.\n", 
                ]
                json = self.generate_result(info)
                self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-anyAPI
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_anyAPI_data(self) -> None:
        fulfillFound = set()
        validated, recorded = False, False
        fulfillNames = self._find_fulfill()
        if fulfillNames:
            for fulfillName in fulfillNames:
                for contract in self.compilation_unit.contracts_derived:
                    for func in contract.functions_declared:
                        # locate the fulfill function 
                        if func.name == fulfillName:
                            fulfillFound.add(fulfillName)
                            # check the sig and requestID 
                            for internalCall in func.internal_calls:
                                callFunc = internalCall.function
                                if callFunc and callFunc.name == "_validateChainlinkCallback":
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
                                    "Either 'validateChainlinkCallback' or 'recordChainlinkFulfillment'" +
                                    " should be used in ", func, " for validation.\n", 
                                ]
                                json = self.generate_result(info)
                                self.results.append(json)
                            self._check_oracle_response(func, func.parameters[1:])
                            self._check_revert_in_fallback(func)
            missingFulfill = [name for name in fulfillNames if name not in fulfillFound]
            if missingFulfill:
                self.logger.error(f"Fail to find callback function: {missingFulfill} in contracts.")
        else:
            self.logger.error("Fail to find 'buildChainlinkRequest' or 'buildOperatorRequest'.")
            
    def _find_fulfill(self) -> Set[str]:
        """
        Get fulfill function name according to the invocation of building-request
        :return: fulfill function names
        """
        fulfillNames = set()
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for node in func.nodes:
                    fulfillName = None
                    fulfilled1, fulfilled2 =False, False
                    if "_buildOperatorRequest" in str(node.expression):
                        fulfilled1 = True
                    elif "_buildChainlinkRequest" in str(node.expression):
                        fulfilled2 = True
                        if "this" not in str(node.expression):
                            info: DETECTOR_INFO = [
                                "'_buildChainlinkRequest' in ", node, " sets up other contract " +
                                "as callback, remember to add 'addChainlinkExternalRequest' in " +
                                "corresponding contract.\n", 
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)
                    if fulfilled1 or fulfilled2:
                        match = re.search(r'this\.([^.]+)', str(node.expression))
                        # use 'this' in the selector in building-request
                        if match:
                            fulfillName = match.group(1)
                        # use predefined selector in building-request
                        elif fulfilled1 and node.variables_read[1].source_mapping:
                            # the fulfill function is selected at arg[1]
                            match = re.search(r'this\.([^.]+)',
                                              node.variables_read[1].source_mapping.content)
                            if match:
                                fulfillName = match.group(1)
                        elif fulfilled2 and node.variables_read[2].source_mapping:
                            # the fulfill function is selected at arg[2]
                            match = re.search(r'this\.([^.]+)',
                                              node.variables_read[2].source_mapping.content)
                            if match:
                                fulfillName = match.group(1)
                        if fulfillName:
                            fulfillNames.add(fulfillName)
                        else:
                            self.logger.error("Fail to find callback selector in building-request!")
        return fulfillNames
    
    ###################################################################################
    ###################################################################################
    # region Chainlink-functions
    ###################################################################################
    ###################################################################################
        
    def _detect_chainlink_functions_data(self) -> None:
        fulfillFound = False
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_override and func.name == "fulfillRequest":
                    fulfillFound = True
                    self._check_oracle_response(func, func.parameters)
                    self._check_revert_in_fallback(func)
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
                requestCounteer = 0
                respChecked = set()
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, HighLevelCall):
                            if ir.function_name in self.deprecatedChainlinkAPIs:
                                info: DETECTOR_INFO = [
                                    "Deprecated function invoked in ", node, " Do not use it.\n",
                                ]
                                json = self.generate_result(info)
                                self.results.append(json)
                            elif ir.function_name in ["latestRoundData", "getRoundData"]:
                                # Extracting the oracle response in the return value
                                matched = re.match(r"\s*\(([^)]*?)\)\s*=", str(node.expression))
                                if not matched:
                                    self.logger.error("Fail to extract return value of oracle request.")    
                                else:
                                    vars = [v.strip() for v in matched.group(1).split(",")]
                                    if len(vars) != 5:
                                        self.logger.error("The format of oracle response is incorrect.") 
                                    else:
                                        requestCounteer += 1
                                        if requestCounteer > 1:
                                            info: DETECTOR_INFO = [
                                                "Sending multiple requests ", node, "in a single call.\n", 
                                            ]
                                            json = self.generate_result(info)
                                            self.results.append(json)
                                        v2, v3, v5 = vars[1], vars[2], vars[4]
                                        # The value and timestamp should be checked
                                        if v2 == "None" or v3 == "None":
                                            info: DETECTOR_INFO = [
                                                "value and timestemp of response ", node," not vaildated.\n",
                                            ]
                                            json = self.generate_result(info)
                                            self.results.append(json)
                                        # answeredInRound is deprecated and should be None
                                        if v5 != "None":
                                            info: DETECTOR_INFO = [
                                                "'answeredInRound' is deprecated.", node, " Do not use it.\n", 
                                            ]
                                            json = self.generate_result(info)
                                            self.results.append(json)
                                        self._check_oracle_response(func, node.variables_written)

    ###################################################################################
    ###################################################################################
    # region Chainlink-dataStream
    ###################################################################################
    ###################################################################################
    
    def _detect_chainlink_dataStream(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                # Extract the validated oracle response
                verifiedReport = None
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, HighLevelCall) and ir.function_name == "verify":
                                verifiedReport = node.variables_written[0]
                                self._check_revert_in_fallback(func)
                        if isinstance(ir, SolidityCall) and ir.function.name == "abi.decode()":
                            if verifiedReport:
                                if is_dependent(node.variables_written[0], verifiedReport, func):
                                    finalReport = node.variables_written[0]
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
                                                        info: DETECTOR_INFO = [
                                                            "'validFromTimestamp' or 'expiresAt' of " +
                                                        " response ", node," not validated.\n", 
                                                        ]
                                                        json = self.generate_result(info)
                                                        self.results.append(json)
                                                    if not valueChecked:
                                                        info: DETECTOR_INFO = [
                                                            "'price' of response", node," not validated.\n",
                                                        ]
                                                        json = self.generate_result(info)
                                                        self.results.append(json)
                                                    if "4" in str(finalReport.type) and not marketChecked:
                                                        info: DETECTOR_INFO = [
                                                            "'marketStatus' of response", node,
                                                            " not validated.\n",
                                                        ]
                                                        json = self.generate_result(info)
                                                        self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################
    def _check_tainted_vrf(self, func:Function, taintPool: List[Variable]) -> None:
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, Binary):
                    if ir.type in [BinaryType.POWER, BinaryType.MULTIPLICATION, BinaryType.DIVISION,
                                       BinaryType.MODULO, BinaryType.ADDITION, BinaryType.SUBTRACTION,
                                       BinaryType.LEFT_SHIFT, BinaryType.RIGHT_SHIFT, BinaryType.AND,
                                       BinaryType.CARET, BinaryType.OR]:
                        if len(ir.node.variables_read) > 1:
                            for val in ir.node.variables_read:
                                for taint in taintPool:
                                    if is_dependent(val, taint, func):
                                        for var in ir.node.variables_written:
                                            if var not in taintPool:
                                                taintPool.append(var)
                                        info: DETECTOR_INFO = [
                                            "Random value influenced ", node, " by user-controlled variable.\n",
                                        ]
                                        json = self.generate_result(info)
                                        self.results.append(json)
                if isinstance(ir, InternalCall) and ir.function:
                    self._check_tainted_vrf(ir.function, taintPool)
                
    def _detect_chainlink_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.name == "fulfillRandomWords":
                    idChecked = False
                    # check tainted vrf
                    self._check_revert_in_fallback(func)
                    self._check_tainted_vrf(func, [func.parameters[1]])
                    for node in func.nodes:
                        # check the validation of returned ID
                        if node.is_conditional(False):
                            if func.parameters[0] in node.variables_read:
                                idChecked = True
                        # check use before validation
                        else:
                            for varRead in node.variables_read:
                                if is_dependent(varRead, func.parameters[1], func) and not idChecked:
                                    info: DETECTOR_INFO = [
                                        "Oracle response used in ", node, " before validating request ID.\n",
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
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                requestCounter = 0
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, HighLevelCall):
                            if ir.function_name in self.deprecatedPythAPIs:
                                info: DETECTOR_INFO = [
                                    "Deprecated function invoked.", node, " Do not use this function.\n", 
                                ]
                                json = self.generate_result(info)
                                self.results.append(json)
                            # check the vaildation of oracle response
                            elif ir.function_name in self.PythFeedAPIs:
                                unsafeAPI = False
                                if ir.function_name in ["getEmaPriceUnsafe", "getPriceUnsafe"]:
                                    # the timestamp of the response of these apis need to be checked 
                                    unsafeAPI = True
                                response = ir.node.variables_written[0]
                                if response:
                                    requestCounter += 1
                                    if requestCounter > 1:
                                        info: DETECTOR_INFO = [
                                            "Sending multiple requests ", node, "in a single call.\n", 
                                        ]
                                        json = self.generate_result(info)
                                        self.results.append(json)
                                    # check the validation of oracle response
                                    valueChecked, timeChecked = False, False
                                    for node in func.nodes:
                                        if node.is_conditional(False):
                                            if response in node.variables_read:
                                                if ".price" in str(node.expression):
                                                    valueChecked = True
                                                if ".publishTime" in str(node.expression):
                                                    timeChecked = True
                                        else:
                                            if unsafeAPI:
                                                for varRead in node.variables_read:
                                                    if is_dependent(varRead, response, func):
                                                        if not valueChecked or not timeChecked:
                                                            info: DETECTOR_INFO = [
                                                                "'price' or 'publishTime' of response",
                                                                node,
                                                                " not validated.\n", 
                                                            ]
                                                            json = self.generate_result(info)
                                                            self.results.append(json)
                                            else:
                                                for varRead in node.variables_read:
                                                    if is_dependent(varRead, response, func):
                                                        if not valueChecked:
                                                            info: DETECTOR_INFO = [
                                                            "'price' of response ", node, 
                                                            " not validated.\n", 
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
                for libCall in func.library_calls:
                    if libCall.function_name == "parsePayloadHeader":
                        # Extracting the result in payload
                        timestamp, channel = None, None
                        for val in libCall.node.variables_written:
                            if str(val.type) == "uint64":
                                timestamp = val
                            elif str(val.type) == "PythLazerLib.Channel":
                                channel = val
                        if timestamp and channel:
                            self._check_oracle_response(func, [timestamp, channel])
                            self._check_revert_in_fallback(func)
                        else:
                            info: DETECTOR_INFO = [
                                "'timestamp' and 'channel' of response ", libCall.node, " not validated.\n", 
                            ]
                            json = self.generate_result(info)
                            self.results.append(json)
                    if libCall.function_name == "parseFeedValueUint64":
                        for val in libCall.node.variables_written:
                            if str(val.type) == "uint64":
                                self._check_oracle_response(func, [val])

    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.name == "entropyCallback":
                    idChecked = False
                    # check tainted vrf
                    self._check_revert_in_fallback(func)
                    self._check_tainted_vrf(func, [func.parameters[2]])
                    for node in func.nodes:
                        # check the validation of returned ID
                        if node.is_conditional(False):
                            if func.parameters[0] in node.variables_read:
                                idChecked = True
                        # check use before validation
                        else:
                            for varRead in node.variables_read:
                                if is_dependent(varRead, func.parameters[2], func) and not idChecked:
                                    info: DETECTOR_INFO = [
                                        "Oracle response used in ", node, " before validating request ID.\n",
                                    ]
                                    json = self.generate_result(info)
                                    self.results.append(json)  

    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################
    def _detect_redStone(self) -> None:
        self._detect_chainlink_dataFeed()