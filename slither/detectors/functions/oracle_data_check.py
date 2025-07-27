import re
from logging import Logger
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.core.solidity_types.mapping_type import MappingType
from slither.slither import Slither
from slither.slithir.operations.binary import Binary, BinaryType
from slither.slithir.operations.high_level_call import HighLevelCall
from slither.slithir.operations.library_call import LibraryCall
from slither.slithir.operations.operation import Operation
from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO)
from slither.core.cfg.node import Node
from slither.core.variables.variable import Variable
from slither.core.declarations.function import Function
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.slithir.operations.internal_call import InternalCall
from slither.analyses.data_dependency.data_dependency import is_dependent

# Map the inherited contract to the oracle service
# Format: {inherited_contract_name: oracle_service_name, ...}
SERVICE_MAP = {
    "AggregatorV3Interface": "chainlink_data_feed",
    "AccessControlledOffchainAggregator": "chainlink_data_feed",
    "StreamsLookupCompatibleInterface": "chainlink_data_stream",
    "ChainlinkClient": "chainlink_any_api",
    "FunctionsClient": "chainlink_functions",
    "VRFConsumerBaseV2": "chainlink_vrf_Sub",
    "VRFV2WrapperConsumerBase": "chainlink_vrf_DF",
    "VRFConsumerBaseV2Plus": "chainlink_vrf_Sub",
    "VRFV2PlusWrapperConsumerBase": "chainlink_vrf_DF",
    "IPyth": "pyth_price_feed",
    "PythLazer": "pyth_price_stream",
    "IEntropyConsumer": "pyth_vrf",
    "IChronicle": "chronicle",
    "RedstoneConsumerBase": "redStone",
}

# 仅对fulfill检查回滚，其他的不再检查
# 仅对合约/订阅付款检查取款，其他不再检查

# chainlink-data-feed
# 分析AggregatorV3和AccessControlledOffchainAggregator，已弃用FeedRegistryInterface
# 实现方式为实例化Aggregator后直接调用API
# 值检查，修改检查，3类请求检查，过时API检查，参数及实例化访问控制，中断和更新
CH_FEED_APIS = ["getRoundData", "latestRoundData"]#highlevel
CH_DEPR_AGGRE_APIS = ["getAnswer", "getTimestamp",
    "latestAnswer", "latestTimestamp", "latestRound"]#highlevel

# chainlink-data-stream
# 分析IVerifierProxy(verify)和StreamsLookupCompatibleInterface(checkErrorHandler)
# 实现方式为外部触发器回调performUpkeep（external），实例化IVerifierProxy并verify验证
# 值检查，修改检查，验证检查，调用授权扣费无需取款，错误处理，实例化访问控制，中断和更新
# 由于返回值是复合结构，不考虑嵌套检查；调用专门函数验证，不考虑嵌套函数验证；可能误报但不漏报
CH_STREAM_VERIFY = ["verify"] #highlevel

# chainlink-anyAPI
# 分析ChainlinkClient
# 实现方式为创建并发送请求，合约中扣费，指定回调函数指定接口验证
# 值检查，ID及验证检查，修改检查，取款检查、取消检查，回滚检查，所有均需访问控制、中断和更新
CH_ANYAPI_INIT = ["_setChainlinkOracle", "_setChainlinkToken",
    "_setPublicChainlinkToken"] #internal
CH_ANYAPI_REQUEST = ["_buildChainlinkRequest", "_buildOperatorRequest",
    "_sendChainlinkRequest", "_sendChainlinkRequestTo", "_sendOperatorRequest",
    "_sendOperatorRequestTo", "_rawRequest", "_cancelChainlinkRequest",
    "_addChainlinkExternalRequest", "_useChainlinkWithENS",
    "_updateChainlinkOracleWithENS"] #internal
CH_ANYAPI_VERIFY = ["_validateChainlinkCallback", "recordChainlinkFulfillment"]

# chainlink-function
# 分析FunctionsClient和FunctionsRequest
# 实现方式为实例化FunctionsClient给router调用权限，创建发送请求订阅扣费，需访问控制中断更新
# 覆写internal函数并验证（handleOracleFulfillment中验证），需要中断和更新
CH_FUNCTIONS_REQUEST = ["_sendRequest"] #internal
CH_FUNCTIONS_FULFILL = "fulfillRequest" #override，不被其他调用

# chainlink-vrf，目前支持V2和V2Plus两个版本
# 前者依赖VRFConsumerBaseV2和VRFV2WrapperConsumerBase，对应订阅方式和付款方式
# 后者依赖VRFConsumerBaseV2Plus和VRFV2PlusWrapperConsumerBase，对应订阅和付款
# 对于订阅Sub,需要实例化VRFConsumerBase用于回调,实例化VRFCoordinatorV2Interface用于请求
#             2.5中仅需实例化VRFConsumerBase,其中完成了对IVRFCoordinatorV2Plus的实例化
#             2中有管理消费的接口highlevel,2类请求"requestRandomWords"都为highlevel
# 对于付款DF,实现方式为实例化VRFV2WrapperConsumerBase，发送请求和回调
#                         VRFV2PlusWrapperConsumerBase,额外提供一种支付方式
#                         请求都为internal
# 覆写internal函数并验证（rawFulfillRandomWords中验证），需要中断和更新
CH_VRFSUB_REQUEST = ["requestRandomWords", "createSubscription",
    "requestSubscriptionOwnerTransfer", "acceptSubscriptionOwnerTransfer"
    "addConsumer", "removeConsumer", "cancelSubscription"] #highlevel
CH_VRFDF_REQUEST = ["requestRandomness", "requestRandomnessPayInNative"] #internal
CH_VRF_FULFILL = "fulfillRandomWords" #override，不被其他调用

# pyth-data-feed
# 分析IPyth
# 实现方式为实例化IPyth,调用者支付费用并发送请求,返回为结构体
# 由于更新是请求的前置条件,这里直接检测请求不检测更新;由于返回值是复合结构，不考虑嵌套检查；
# 值检查,修改检查,多次/循环请求,过期API,无需权限,需检查中止和更新
PYTH_FEED_SAFE_APIS = ["getPriceNoOlderThan", "getEmaPriceNoOlderThan"]# highlevel
PYTH_FEED_UNSAFE_APIS = ["getPriceUnsafe", "getEmaPriceUnsafe"]# highlevel
PYTH_FEED_UPDATE = ["parsePriceFeedUpdates", "parsePriceFeedUpdatesUnique",
    "updatePriceFeeds", "updatePriceFeedsIfNecessary"]# highlevel
PYTH_DEPRECATED_APIS = ["getPrice", "getEmaPrice", "getValidTimePeriod"]# highlevel

# pyth-data-stream
# 分析PythLazer
# 实现方式为实例化PythLazer，同样由触发器和payable的回调函数中调用verifyUpdate验证，调用者付费
PYTH_STREAM_VERIFY = ["verifyUpdate"]#highlevel

# pyth=vrf
# 分析IEntropyConsumer用于callback,IEntropy用于发送请求
# 实现方式是实例化IEntropy，调用者付费并发送请求，不需要访问控制，需要中断和更新
# 回调指定internal函数entropyCallback（_entropyCallback已验证），需要中断和更新
PYTH_VRF_REQUEST = ["request", "requestWithCallback"] #highlevel
PYTH_VRF_FULFILL = "entropyCallback" #override，不被其他调用
PYTH_VRF_BUILD = ["register", "withdraw", "withdrawAsFeeManager", "setFeeManager",
    "setProviderFee", "setProviderFeeAsFeeManager", "setProviderUri"] #highlevel

# chronicle
# 分析ScribeOptimistic或者Ichronicle
# 实现方式是，实例化Ichronicle，直接调用
CHRONICLE_FEED_APIS = ["read", "readWithAge", "tryRead", "tryReadWithAge"]#highlevel

# redstone
# 分析RedstoneConsumerBytesBase和RedstoneConsumerNumbericBase
# 实现方式是直接调用
REDSTONE_FEED_APIS = ["getOracleBytesValueFromTxMsg", "getOracleBytesValuesFromTxMsg",
    "getOracleNumericValueFromTxMsg", "getOracleNumericValuesFromTxMsg",
    "getOracleNumericValuesAndTimestampFromTxMsg",
    "getOracleNumericValuesWithDuplicatesFromTxMsg"]#internal

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
                elif service == "chainlink_vrf_Sub":
                    self._detect_chainlink_vrf()
                elif service == "chainlink_vrf_DF":
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
    # region Chainlink-dataFeed
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_dataFeed(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, hCall in func.high_level_calls:
                    if hCall.function_name in CH_FEED_APIS:
                        if hCall.node.variables_written:
                            self._check_chainlink_round_data(hCall.node)
                            self.check_tamperred_resp(func, set(hCall.node.variables_written))
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", hCall.node,
                                " not checked but returned directly.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    def _check_chainlink_round_data(self, node:Node) -> None:
        responses = []
        # Extract the data fields in the response
        matched = re.match(r"\s*\(([^)]*?)\)\s*=", str(node.expression))
        if not matched:
            self.logger.error(f"Fail to extract the return value in {node.expression}.")
        else:
            responses = [v.strip() for v in matched.group(1).split(",")]
            if len(responses) != 5:
                self.logger.error(f"The data fields of {node.expression} is incorrect.")
        # The data field of answer, startedAt and answeredInRound
        v2, v3, v5 = responses[1], responses[2], responses[4]
        if v2 == "None" or v3 == "None":
            info: DETECTOR_INFO = ["CWE-252: answer and startedAt of data feed in ",
                node," not vaildated.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        if v5 != "None":
            info: DETECTOR_INFO = ["CWE-477: answeredInRound is deprecated but used in ",
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
                        if highCall.function_name in CH_STREAM_VERIFY:
                            if highCall.node.variables_written:
                                vReport = highCall.node.variables_written[0]
                            else:
                                info: DETECTOR_INFO = ["CWE-252: the verified value in ",
                                    highCall.node, " not checked.\n"]
                                json = self.generate_result(info)
                                self.results.append(json)
                    if vReport:
                        decodes = [s for s in func.solidity_calls
                                   if s.function.name == "abi.decode()"]
                        for decode in decodes:
                            for val in decode.node.variables_read:
                                if is_dependent(val, vReport, func):
                                    if decode.node.variables_written:
                                        report = decode.node.variables_written[0]
                                        self.check_tamperred_resp(func, {report})
                                        self._check_chainlink_stream_data(func, report)
                                    else:
                                        info: DETECTOR_INFO = ["CWE-252: decoded value in ",
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
                finalReport," not checked.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        if not valueChecked:
            info: DETECTOR_INFO = ["CWE-252: price in ", finalReport," not checked.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        if "4" in str(finalReport.type) and not marketChecked:
            info: DETECTOR_INFO = ["CWE-252: marketStatus of response in ",
                finalReport, " not checked.\n"]
            json = self.generate_result(info)
            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Chainlink-anyAPI
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_anyAPI(self) -> None:
        # 由于该服务的回调函数由用户指定，所以可能会有多个回调函数
        # fulfillFuncs记录从预言机请求中提取的fulfill function
        # fulfillFound记录合约中已找到的fulfill function
        fulfillFuncs = self._get_fulfills()
        fulfillFound = set()
        if not fulfillFuncs:
            return
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.name in fulfillFuncs:
                    validated, recorded = False, False
                    fulfillFound.add(func.name)
                    for interCall in func.internal_calls:
                        if interCall.function:
                            if interCall.function.name == "_validateChainlinkCallback":
                                validated = True
                        for modififierCall in func.modifiers:
                            if modififierCall.name == "recordChainlinkFulfillment":
                                recorded = True
                    if validated and recorded:
                        info: DETECTOR_INFO = [
                            "CWE-345: Use either 'validateChainlinkCallback' or " +
                            "'recordChainlinkFulfillment' in ", func," not both.\n", 
                        ]
                        json = self.generate_result(info)
                        self.results.append(json)
                    elif not validated and not recorded:
                        info: DETECTOR_INFO = [
                            "CWE-345: use either _validateChainlinkCallback or " +
                            "recordChainlinkFulfillment in ", func, " for validation.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    self.check_oracle_response(func, set(func.parameters[1:]))
                    self.check_tamperred_resp(func, set(func.parameters[1:]))
                    idChecked = self.check_response_id(func)
                    if not idChecked:
                        info: DETECTOR_INFO = [
                            "CWE-345: response ID of the fulfill ",
                             func," not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
        fulfillnotfound = [func for func in fulfillFuncs if func not in fulfillFound]
        if fulfillnotfound:
            self.logger.error(f"Fail to find callback function: {fulfillnotfound}.")

    def _get_fulfills(self) -> set[str]:
        fulfills = set()
        for func in self.compilation_unit.functions:
            for interCall in func.internal_calls:
                callFunc = interCall.function
                if not callFunc:
                    continue
                typeOp, typeCh =False, False
                if callFunc.name == "_buildOperatorRequest":
                    typeOp = True
                elif callFunc.name == "_buildChainlinkRequest":
                    typeCh = True
                    if "this" not in str(interCall.node.expression):
                        info: DETECTOR_INFO = [
                            "CWE703: _buildChainlinkRequest in ", interCall.node, 
                            " sets up other contract as callback, remember to add " +
                            "_addChainlinkExternalRequest in corresponding contract.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                fulfillName = self._get_fulfill_name(interCall.node, typeOp, typeCh)
                if fulfillName:
                    fulfills.add(fulfillName)
        if not fulfills:
            self.logger.error("Fail to find fulfill function in the contract.")
        return fulfills

    def _get_fulfill_name(self, node: Node, typeOp: bool, typeCh: bool ) -> str:
        fulfillName = ""
        if not typeOp and not typeCh:
            return fulfillName
        # if use 'this' in function selector
        match = re.search(r'this\.([^.]+)', str(node.expression))
        # if use predefined selector
        if not match:
            if typeOp and node.variables_read[1].source_mapping:
                # function selector is in arg[1]
                match = re.search(r'this\.([^.]+)',
                                    node.variables_read[1].source_mapping.content)
            elif typeCh and node.variables_read[2].source_mapping:
                # function selector is in arg[2]
                match = re.search(r'this\.([^.]+)',
                                    node.variables_read[2].source_mapping.content)
        if match:
            fulfillName = match.group(1)
        else:
            self.logger.error("Fail to get fulfill selector in oracle request.")
        return fulfillName

    ###################################################################################
    ###################################################################################
    # region Chainlink-functions
    ###################################################################################
    ###################################################################################

    def _detect_chainlink_functions(self) -> None:
        fulfillFound = False
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_implemented and func.name == CH_FUNCTIONS_FULFILL:
                    fulfillFound = True
                    idChecked = self.check_response_id(func)
                    if not idChecked:
                        info: DETECTOR_INFO = [
                            "CWE-345: response ID of the fulfill ",
                             func," not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    self.check_oracle_response(func, set(func.parameters[1:]))
                    self.check_tamperred_resp(func, {func.parameters[1]})
        if not fulfillFound:
            self.logger.error("Fail to find the fulfill function.")

    ###################################################################################
    ###################################################################################
    # region Chainlink-VRF
    ###################################################################################
    ###################################################################################
    def _detect_chainlink_vrf(self) -> None:
        fulfillFound = False
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_implemented and func.name == CH_VRF_FULFILL:
                    fulfillFound = True
                    idChecked = self.check_response_id(func)
                    if not idChecked:
                        info: DETECTOR_INFO = [
                            "CWE-345: response ID of the fulfill ",
                             func," not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    self.check_tamperred_resp(func, {func.parameters[1]})
        if not fulfillFound:
            self.logger.error("Fail to find the fulfill function.")

    ###################################################################################
    ###################################################################################
    # region Pyth-priceFeed
    ###################################################################################
    ###################################################################################
    def _detect_pyth_priceFeed(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                for _, hCall in func.high_level_calls:
                    requested, timeChecked = False, False
                    if hCall.function_name in PYTH_FEED_SAFE_APIS:
                        requested = True
                        timeChecked = True
                    if hCall.function_name in PYTH_FEED_UNSAFE_APIS:
                        requested = True
                    if requested:
                        if hCall.node.variables_written:
                            resp = hCall.node.variables_written[0]
                            self._check_pyth_feed_data(func, resp, timeChecked)
                            self.check_tamperred_resp(func, {resp})
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", hCall.node,
                                " not checked but returned directly.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    def _check_pyth_feed_data(self, func:Function, resp:Variable, safe:bool) -> None:
        valueChecked, timeChecked = False, False
        if safe:
            timeChecked = True
        for node in func.nodes:
            if node.is_conditional(False):
                for var in node.variables_read:
                    if is_dependent(var, resp, node.function):
                        if ".price" in str(node.expression):
                            valueChecked = True
                        if ".publishTime" in str(node.expression):
                            timeChecked = True
        if not valueChecked:
            info: DETECTOR_INFO = ["CWE-252: price of oracle response in ",
                resp, " not checked.\n"]
            json = self.generate_result(info)
            self.results.append(json)
        if not timeChecked:
            info: DETECTOR_INFO = ["CWE-252: publishTime of oracle response in ",
                resp, " not checked.\n"]
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
                for libCall in func.library_calls:
                    if libCall.function_name == "parsePayloadHeader":
                        verified = False
                        for _, highCall in func.high_level_calls:
                            if highCall.function_name == "verifyUpdate":
                                verified = True
                        if not verified:
                            info: DETECTOR_INFO = ["CWE-345: oracle response in ",
                                func, " not verified.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                        timestamp, channel = None, None
                        for val in libCall.node.variables_written:
                            if str(val.type) == "uint64":
                                timestamp = val
                            elif str(val.type) == "PythLazerLib.Channel":
                                channel = val
                        if timestamp and channel:
                            self.check_oracle_response(func, {timestamp, channel})
                        else:
                            info: DETECTOR_INFO = ["CWE-252: timestamp or channel in ",
                                libCall.node, " not checked.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)
                    elif libCall.function_name == "parseFeedValueUint64":
                        if libCall.node.variables_written:
                            vals = {val for val in libCall.node.variables_written
                                    if str(val.type) == "uint64"}
                            self.check_oracle_response(func, vals)
                            self.check_tamperred_resp(func, vals)
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", libCall.node,
                                " not checked but returned directly.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Pyth-VRF
    ###################################################################################
    ###################################################################################

    def _detect_pyth_vrf(self) -> None:
        fulfillFound = False
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_implemented and func.name == PYTH_VRF_FULFILL:
                    fulfillFound = True
                    idChecked = self.check_response_id(func)
                    if not idChecked:
                        info: DETECTOR_INFO = [
                            "CWE-345: response ID of the fulfill ",
                             func," not checked.\n"]
                        json = self.generate_result(info)
                        self.results.append(json)
                    self.check_tamperred_resp(func, {func.parameters[2]})
        if not fulfillFound:
            self.logger.error("Fail to find the fulfill function.")

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
                        if hCall.node.variables_written:
                            # check whether some values of response are ignored
                            self.check_ignored_resp(hCall)
                            # verify the data check
                            self.check_oracle_response(func, set(hCall.node.variables_written))
                            # verify the unprotected tamper
                            self.check_tamperred_resp(func, set(hCall.node.variables_written))
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", hCall.node,
                                " not checked but returned directly.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region RedStone
    ###################################################################################
    ###################################################################################

    def _detect_redStone(self) -> None:
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions_declared:
                if func.is_virtual:
                    continue
                for ic in func.internal_calls:
                    if ic.function and ic.function.name in REDSTONE_FEED_APIS:
                        if ic.node.variables_written:
                            self.check_oracle_response(func, set(ic.node.variables_written))
                            self.check_tamperred_resp(func, set(ic.node.variables_written))
                        else:
                            info: DETECTOR_INFO = ["CWE-252: the value in ", ic.node,
                                " not checked but returned directly.\n"]
                            json = self.generate_result(info)
                            self.results.append(json)

    ###################################################################################
    ###################################################################################
    # region Public
    ###################################################################################
    ###################################################################################

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
                if (isinstance(ir, (LibraryCall, InternalCall, HighLevelCall))
                        and isinstance(ir.function, Function)):
                    for var in ir.node.variables_read:
                        possibleCheckedResps = [resp for resp in resps
                            if resp not in checkedResps and is_dependent(var, resp, func)]
                        if possibleCheckedResps:
                            i = self._get_index(str(var.name), str(ir.node.expression))
                            if self._check_param(ir.function, i):
                                checkedResps.update(possibleCheckedResps)
        for var in resps:
            if var not in checkedResps:
                info: DETECTOR_INFO = ["CWE-252: oracle response ", var, " not checked.\n"]
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

    def _check_param(self, func: Function, index:int, visited=None) -> bool:
        """
        Verify the value check of specified variable in invoked function
        :param func(Function):  the invoked function
        :param index(int):      the index of the variable in the paremeter list
        :return:                the specified variable is checked in the function
        """
        if visited is None:
            visited = set()
        if func in visited:
            return False
        visited.add(func)
        if index < 0:
            return False
        for node in func.nodes:
            if node.is_conditional(False):
                for var in node.variables_read:
                    if is_dependent(var, func.parameters[index], func):
                        return True
            for ir in node.irs:
                # the response may be checked in function invocation
                if (isinstance(ir, (LibraryCall, InternalCall, HighLevelCall))
                        and isinstance(ir.function, Function)):
                    for var in ir.node.variables_read:
                        if is_dependent(var, func.parameters[index], func):
                            i = self._get_index(str(var.name), str(ir.node.expression))
                            return self._check_param(ir.function, i, visited)
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

    def _check_tamperred_resp(self, func: Function, contract:Contract,
                              resps: set[Variable], visited=None) -> None:
        if visited is None:
            visited = set()
        if func in visited:
            return
        visited.add(func)
        irs = [ir for node in func.nodes for ir in node.irs]
        for ir in irs:
            if (isinstance(ir, (LibraryCall, InternalCall, HighLevelCall))
                    and isinstance(ir.function, Function)):
                self._check_tamperred_resp(ir.function, contract, resps, visited)
            if len(ir.node.variables_read) < 2 or not self._is_calc(ir):
                continue
            respInCalc = None
            isRespInCalc = False
            for var in ir.node.variables_read:
                for resp in resps:
                    if is_dependent(var, resp, contract):
                        isRespInCalc = True
                        respInCalc = var
            if isRespInCalc:
                for var in ir.node.variables_read:
                    for param in func.parameters:
                        if is_dependent(var, param, func) and var != respInCalc:
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

    def check_response_id(self, func:Function) -> bool:
        # 默认id是第一个参数，而且不考虑嵌套检查
        requestID = func.parameters[0]
        if not requestID:
            return False
        for node in func.nodes:
            for var in node.variables_read:
                if is_dependent(var, requestID, func):
                    if node.is_conditional(False):
                        return True
                    for var in node.variables_written:
                        if isinstance(var.type, MappingType):
                            return True
        return False

    def check_ignored_resp(self, hCall:HighLevelCall) -> None:
        if hCall.function_name in ["tryRead", "readWithAge"]:
            if len(hCall.node.variables_written) != 2:
                info: DETECTOR_INFO = ["CWE-252: some values of the response in ",
                                        hCall.node, " should not been ignored.\n"]
                json = self.generate_result(info)
                self.results.append(json)
        elif hCall.function_name == "tryReadWithAge":
            if len(hCall.node.variables_written) != 3:
                info: DETECTOR_INFO = ["CWE-252: some values of the response in ",
                                        hCall.node, " should not been ignored.\n"]
                json = self.generate_result(info)
                self.results.append(json)
