ANALYZE_CONTRACT_SUMMARY = """
You are a solidity smart contract auditor.
Analyze the contract summary provided.

YOUR TASKS:
- Infer the business domain.
- Infer roles, their capabilities, and target resources.
- Identify which state variables are used for access control.

INPUT:
Contract name:{name}
Imports:{imports}
Inheritances:{inheritances}
Event definitions:{events}
State Variables:{state_vars}
Entry Functions:{entry_funcs}

Provide concise and factual information strictly based on the input.
If any item cannot be inferred, leave it empty. Do not fabricate or guess.

Output ONLY valid JSON. 
{{
    "business": "string",
    "role_capability_resource": [
        {{
            "role": "string",
            "operation": "string",
            "resource": "string"
        }}
    ],
    "access_control_state": []
}}
"""

ANALYZE_AC_CONFIG = """
You are a solidity smart contract auditor.
Analyze ONLY access control issues related to the given state variable based on provided information.

Output MUST be valid JSON and follow exactly one of the schemas below.
All textual fields must be concise and factual.

If vulnerable:
{
  "vulnerable": true,
  "confidence": 0.0-1.0,
  "vulnerability_type": "",
  "affected_variable_and_functions": ["<variable> in <function>"],
  "severity": "Low | Medium | High",
  "description_and_impact": "what is wrong & what property is violated",
  "proof_of_concept": "exploit steps or minimal pseudocode",
  "recommendation": "concrete bullet-style suggestions",
}

If not vulnerable or the input is inconsistent or insufficient to reach a reliable conclusion:
{
  "vulnerable": false,
  "justification": ""
}

INPUT:
Contract Name:
{contract_name}
Solidity Version:
{solidity_version}
Contract Summary:
{contract_summary}
Access Control Variable:
{access_control_state}
Functions Reading/Writing This Variable:
{functions_rw_state}
"""

INFER_ACCESS_CONTROL = """
You are a solidity smart contract auditor.
Infer the access control rules (ACRules) for current function based on provided information.

Each ACRule follows this structure:
{
  "subject": "Who, e.g., CALLER, ROLE:ADMIN, ADDRESS:0x123...>",
  "operation": "<TYPE>:<TARGET>
        e.g., CALL:function_name, TRANSFER:ETH, MODIFY:state_name",
  "condition": "<CONDITION_EXPR>
        Use ATOMIC_PREDICATE, e.g., CALLER == owner, !paused, balance[CALLER] >= x
        Combine with AND / OR, use parentheses to indicate precedence",  
  "provenance": "TYPE:SOURCE;TYPE:SOURCE;...
        e.g., <MODIFIER:onlyOwner;ENTRY:external;LOCAL:if/require>"
}

Output MUST be valid JSON array of ACRules.

INPUT:
Parent Function Code:
{caller_code}
Parent Function Modifiers:
{caller_modifiers}
Parent Function ACRules:
{caller_ac}
Current Function Code:
{callee_code}
Current Function Modifiers:
{callee_modifiers}
Contract Summary:
{contract_summary}
"""

AUDIT_VULNERABILITIES = """
You are a solidity smart contract auditor.
"""

SELF_EVOLVE = """
You are a solidity smart contract auditor with self-evolving capabilities.
"""