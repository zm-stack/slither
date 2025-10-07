from slither.utils.output import Output
from slither.detectors.abstract_detector import (
    AbstractDetector, DetectorClassification, DETECTOR_INFO)

class RiskyMutableProxy(AbstractDetector):
    """
    检测模式：
    - 存在名称类似 'proxyRegistry' 的 state variable 且存在可以修改该变量的外部函数。
    - 实现 isApprovedForAll(...)，且函数体内使用了上述可变变量来验证 whitelist operator。
    """

    ARGUMENT = "risky-mutable-proxy"
    HELP = "Detect modifiable proxy registry address used in isApprovedForAll"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "..."
    WIKI_TITLE = "..."
    WIKI_DESCRIPTION = "..."
    WIKI_EXPLOIT_SCENARIO = "..."
    WIKI_RECOMMENDATION = "..."

    def _detect(self) -> list[Output]:
        results = []

        for contract in self.compilation_unit.contracts_derived:
            mutable_proxy_vars = []
            for func in contract.functions_declared:
                if func.visibility not in ['external', 'public']:
                    continue
                # 查找可变的 proxy registry 变量
                for var in func.state_variables_written:
                    if var.name:
                        name = var.name.lower()
                        if "proxy" in name or "regist" in name:
                            mutable_proxy_vars.append(var)

            if not mutable_proxy_vars:
                continue

            # 查找 isApprovedForAll 的实现
            for func in contract.functions_declared:
                if 'isApprovedForAll' not in func.name:
                    continue
                # 检查函数体内是否使用了上述可变变量
                for var in mutable_proxy_vars:
                    if var in func.variables_read:
                        info: DETECTOR_INFO = ["vulnerability detected: ",
                            contract, " has a mutable proxy registry variable ",
                            var, " used in ",func,
                            ". This can allow an attacker to add a malicious operator.\n"] 
                        res = self.generate_result(info)
                        results.append(res)
        return results