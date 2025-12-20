import os
import re
import json
from openai import OpenAI
from slither.tools.agent.graph_model import CallGraph

class CallGraphAnalyzer:
    """
    Analyze a CallGraph using an LLM:
      - Infer permissions for each function node.
      - Security audit along call paths.
      - Generate corresponding vulnerability reports.
    """
    def __init__(self, callgraph: CallGraph):
        self.cg = callgraph

        # Initialize OpenAI-compatible client.
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key="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"
        )
    
    def _ask(self, prompt: str) -> str:
        """
        Send a prompt to the LLM and return the raw response.
        """
        completion = self.client.chat.completions.create(
            model="openai/gpt-5-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature = 0,
            top_p = 1,
            frequency_penalty = 0,
            presence_penalty = 0
        )
        return completion.choices[0].message.content.strip()
    
    def _extract_output(
            self, text: str) -> tuple[bool, bool, str, list]:
        """
        Parse LLM response and extract the analysis result.
        Returns:
            (updated,vulnerable,permission,vulnerabilities)
            On parse failure,
            returns (False, False, "", []) and prints error.
        """
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1:
                raise ValueError("JSON not found in output")
            json_str = text[start:end+1]
            result = json.loads(json_str)

            perm = result.get("permission", "")
            updated = result.get("updated", False)
            vulnerable = result.get("vulnerable", False)
            vul_list= result.get("vulnerabilities", [])
            if not isinstance(vul_list, list):
                vul_list = [str(vul_list)]
            return updated, vulnerable, perm, vul_list

        except Exception as e:
            print(f"ERROR parsing output: {e}", text)
            return False, False, "", []
        
    def save_report(self, model_output: str) -> None:
        """
        Parse model output, extract JSON list of reports
        """
        out_dir = "output/report"
        os.makedirs(out_dir, exist_ok=True)
        try:
            reports = json.loads(model_output)
        except json.JSONDecodeError:
            json_pattern = r"\[.*\]"
            match = re.search(json_pattern,
                model_output, flags=re.DOTALL)
            if not match:
                raise ValueError(
                    f"No JSON array found \n{model_output}")
            text = match.group(0)
            try:
                reports = json.loads(text)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Decoding JSON failed: {e}\n{text}")
            if not isinstance(reports, list):
                raise ValueError(
                    "JSON is not a list of objects.")
        
        for report in reports:
            title = report.get("title", "untitled")
            title = re.sub(r"[^a-zA-Z0-9_\-]+", "_", title)
            path = os.path.join(out_dir, f"{title}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2,
                    ensure_ascii=False)
            print(f"[+] Saved report to: {path}")


    def entry_point_perm_infer(self) -> None:
        """Infers permission for the entry function."""
        g = self.cg
        prompt = SECURITY_AUDITING_PROMPT.format(
            entry_type=g.entry_type,
            state_vars=g.state_vars,
            caller_function=None,
            call_edge=None,
            callee_function=g.nodes[g.entry_point]
        )
        up, vul, perm, vulns = self._extract_output(
            self._ask(prompt))
        if perm:
            g.nodes[g.entry_point].permission = perm
        if vul:
            prompt = POC_GENERATION_PROMPT.format(
                vul_code=g.nodes[
                    g.entry_point].source.snippet,
                vul_info=vulns,
                call_chain=[],
                state_vars=g.state_vars
            )
            self.save_report(self._ask(prompt))
    
    def func_node_perm_infer(
            self,
            edge_sig:str) -> tuple[bool, bool, str, list]:
        """
        Analyze function nodes of a edge (caller -> callee).
        """
        edge = self.cg.edge_index[edge_sig]
        caller_node = self.cg.nodes[edge.caller]
        callee_node = self.cg.nodes[edge.callee]
        
        prompt = SECURITY_AUDITING_PROMPT.format(
            entry_type=self.cg.entry_type,
            state_vars=self.cg.state_vars,
            caller_function=caller_node,
            call_edge=edge,
            callee_function=callee_node
        )
        return self._extract_output(self._ask(prompt))
    
    def get_call_chain(self) -> list[str]:
        """
        Get the current call chain code snippets.
        """
        chain: list[str] = []
        for func_sig in self.path_stack:
            node = self.cg.nodes.get(func_sig)
            if node:
                chain.append(node.source.snippet)
        return chain

    def dfs(self, func_sig:str):
        """
        Depth-first traversal of the call graph.

        For each edge:
          - Ask the LLM about permission & vulnerabilities.
          - Update callee node's permission.
          - Generate reports for detected vulnerabilities.
          - Recursively traverse updated callees.
        """
        self.path_stack.append(func_sig)
        for edge in self.cg.edges[func_sig]:
            up,vul,perm,vinfo = self.analyze_edge(edge.sig)
            if perm:
                self.cg.nodes[edge.callee].permission = perm
            if vul:
                callee_node = self.cg.nodes[edge.callee]
                prompt = POC_GENERATION_PROMPT.format(
                    vul_code=callee_node.source.snippet,
                    vul_info=vinfo,
                    call_chain=self.get_call_chain(),
                    state_vars=self.cg.state_vars
                )
                self.save_report(self._ask(prompt))
            if not up:
                continue
            if edge.callee in self.path_stack:
                continue
            self.dfs(edge.callee)
        self.path_stack.pop()

SECURITY_AUDITING_PROMPT = """
You are an expert smart contract security analyzer. Your goal is to infer the permission and detect security vulnerabilities in the callee function based on the provided structured data.

Output ONLY valid JSON (must strictly follow)
{{
  "permission": "string",
  "updated": false,
  "vulnerable": false,
  "vulnerabilities": []
}}

permission: inferred permission of the callee
updated: true if it differs from callee_function.permission
vulnerable: true if any security issue is found in callee
vulnerabilities: list of issue descriptions

Task 1 — Infer the callee function's permission using provided data. If callee_node.permission is not empty and differs from your inference → updated=true.

Task 2 — Detect vulnerabilities in the callee (e.g., access control issues, unsafe external calls, reentrancy, misuse of low-level calls). Add each finding as a string. If none → vulnerabilities=[] and vulnerable=false.

Structured Input (fields you will receive)
entry_type: user | fallback | constructor
{entry_type}
state_vars: contract state variable definitions
{state_vars}
caller_function: sig, source, permission
{caller_function}
call_edge:  sig, caller, callee, source, call_type
{call_edge}
callee_function: sig, source, permission
{callee_function}
"""

POC_GENERATION_PROMPT = """
You are an expert smart contract exploit developer.
Use the provided data to analyze each vulnerability, reconstruct its exploit path, and generate an executable PoC.

Output valid JSON only, as a list of objects with:
[
    {
    "title": "string",
    "severity": "high | medium | low",
    "confidence": float(0-1),
    "vul_code_snippet": "string",
    "vul_description": "string",
    "poc": "string",
    "expected_result": "string",
    "remediation": "string"
    }
]

Rules:
- JSON only. No comments or extra text.
- severity follows typical audit standards.
- confidence is your certainty (0-1).
- poc must be an actual exploit example.
- expected_result explains the outcome after running the PoC.

Inputs:
vul_code: function code where vulnerability is found
{vul_code}
vul_info: list of vulnerability descriptions
{vul_info}
call_chain: list of function code representing the call chain
{call_chain}
state_vars: contract state variable definitions
{state_vars}
"""
