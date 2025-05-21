from typing import List
from slither.utils.output import Output
from slither.core.solidity_types.elementary_type import Uint, Int
from slither.slithir.operations.binary import Binary, BinaryType
from slither.detectors.abstract_detector import (
    AbstractDetector, 
    DetectorClassification,
    DETECTOR_INFO,
    ALL_SOLC_VERSIONS_06,
    ALL_SOLC_VERSIONS_07)
 
class OverflowCheck(AbstractDetector):
    """
    Detect arithmetic overflow/underflow in Solidity 0.6.x ~ 0.7.x contracts that do NOT rely on OpenZeppelin SafeMath.
    """
    ARGUMENT = 'overflow'
    HELP = 'Detect integer overflows/underflows (suggest using OpenZeppelin SafeMath ≥3.4)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://docs.openzeppelin.com/contracts/3.x/api/math"
    WIKI_TITLE = "Integer overflow/underflow"
    WIKI_DESCRIPTION = "Before Solidity 0.8, arithmetic operations on `uint`/`int` types wrap on overflow. " + \
        "Contracts compiled with pragma `>=0.6.0 <0.8.0` should adopt SafeMath or explicit " + \
        "checked arithmetic to prevent critical vulnerabilities."
    WIKI_EXPLOIT_SCENARIO =  "An attacker calls `deposit(2**256-1)` so that the balance becomes 0 after overflow, " + \
        "then withdraws all funds."
    WIKI_RECOMMENDATION = "Import `@openzeppelin/contracts/math/SafeMath.sol` (v3.4.x) and wrap all arithmetic " + \
        "with `using SafeMath for uint256;` or upgrade compiler to Solidity ≥0.8 and keep " + \
        "arithmetic outside `unchecked{}` blocks."
    
    VULNERABLE_SOLC_VERSIONS = ALL_SOLC_VERSIONS_06 + ALL_SOLC_VERSIONS_07
    
    RiskyBinaryType = {
        BinaryType.ADDITION: "Addition",
        BinaryType.SUBTRACTION: "Subtraction",
        BinaryType.MULTIPLICATION: "Multiplication",
        BinaryType.DIVISION: "Division",
        BinaryType.MODULO: "Modulo",
        BinaryType.LEFT_SHIFT: "Left Shift",
        BinaryType.RIGHT_SHIFT: "Right Shift"
    }

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            # Skip the SafeMath contract
            if contract.name == "SafeMath":
                continue
            for fnction in contract.functions_declared:
                for node in fnction.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Binary):
                            if ir.type in self.RiskyBinaryType:
                                R1Type = ir.variable_left.type
                                R2Type = ir.variable_right.type
                                if str(R1Type) in Uint or str(R1Type) in Int:
                                    if str(R2Type) in Uint or str(R2Type) in Int:
                                        info: DETECTOR_INFO = [
                                            node,
                                            "Potential overflow/underflow. Consider wrapping with OpenZeppelin SafeMath v3.4 " +\
                                            "or upgrading to Solidity ≥0.8.\n",
                                        ]
                                        json = self.generate_result(info)
                                        results.append(json)
        return results