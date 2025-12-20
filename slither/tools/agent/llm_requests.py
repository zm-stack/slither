import os
import json
from typing import Any
from slither.tools.agent.model_contract import ContractIR
from slither.tools.agent.llm_prompts import(
    ANALYZE_CONTRACT_SUMMARY, ANALYZE_AC_CONFIG
)

class LLM:
    def __init__(self, client):
    # Initialize OpenAI-compatible client.
        self.client =client

    def _log(self, text: str,
             file: str="output/debug.log") -> None:
        """Log input and output in human-readable format."""
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "a", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(text)
            f.write("\n\n")
    
    def _ask(self, model: str, prompt: str) -> str:
        """
        Send a prompt to the LLM and return the raw response.
        """
        completion = self.client.chat.completions.create(
            model = model,
            messages = [{"role": "user", "content": prompt}],
            temperature = 0,
            top_p = 1,
            frequency_penalty = 0,
            presence_penalty = 0
        )
        return completion.choices[0].message.content.strip()

    def analyze_contract_summary(self,
        ir:ContractIR) -> dict[str, Any]:
        """
        Analyze the contract summary using LLM.

        Return:
            inferred business domain,
            roles, capabilities, resources,
            state variables used for access control.
        """
        prompt = ANALYZE_CONTRACT_SUMMARY.format(
            name = ir.contract_name,
            imports = json.dumps(ir.imports, indent=2),
            inheritances = json.dumps(
                ir.inheritances, indent=2),
            events = json.dumps(
                list(ir.events.values()), indent=2),
            state_vars = json.dumps(
                list(ir.state_vars.values()), indent=2),
            entry_funcs = json.dumps(
                list(ir.entry_funcs.values()), indent=2)
        )
        model = "openai/gpt-5.1-codex-mini"
        raw_response = self._ask(model, prompt)

        try:
            response = json.loads(raw_response)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid JSON: {e}\nText:\n{raw_response}")
        self._log(f"PROMPT:\n{prompt}\nOUTPUT:\n{response}")
        
        return response
    
    def analyze_ac_config(self, contract_name:str,
        version:str, summary:dict[str, Any], sv:str,
        funcs:list[str]) -> list[str]:
        """
        Analyze access control config security using LLM.

        Return:
            vulnerabilities on access control configuration.
        """
        prompt = ANALYZE_AC_CONFIG.format(
            contract_name = contract_name,
            solidity_version = version,
            contract_summary = json.dumps(summary, indent=2),
            access_control_state = sv,
            functions_rw_state = json.dumps(funcs, indent=2)
        )
        model = "openai/gpt-5.1-codex-mini"
        raw_response = self._ask(model, prompt)

        try:
            response = json.loads(raw_response)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid JSON: {e}\nText:\n{raw_response}")
        self._log(f"PROMPT:\n{prompt}\nOUTPUT:\n{response}")
        
        return response
    
    def infer_access_control(self, summary:dict[str, Any],
        irc:ContractIR) -> dict[str, Any]:
        """
        Infer access control from each entry point using LLM.
        Return:
            augmented ContractIR with inferred access control.
        """

        for entry, graph in irc.call_graphs.items():
            

        for entry_name, entry_info in ir.entry_funcs.items():
            prompt = f"You are a smart contract auditor.\n"
            prompt += f"Analyze the entry point '{entry_name}' of contract '{ir.contract_name}'.\n"
            prompt += f"Function Summary: {entry_info}\n"
            prompt += f"Additional Info: {json.dumps(summary, indent=2)}\n"
            prompt += "Provide a detailed analysis of access control."

            model = "openai/gpt-5.1-codex-mini"
            raw_response = self._ask(model, prompt)
            augmented_summary[entry_name] = raw_response

            self._log(f"PROMPT:\n{prompt}\nOUTPUT:\n{raw_response}")

        return augmented_summary

    # def analyze_entry_point(self, summary:ContractIR,
    #     data:dict[str, Any]) -> dict[str, Any]:
    #     """
    #     Analyze each entry point of the contract using LLM and return augmented summary.
    #     """
    #     augmented_summary = {}

    #     for entry_name, entry_info in data.get("entry_points", {}).items():
    #         prompt = f"Analyze the entry point '{entry_name}' of contract '{summary.name}'.\n"
    #         prompt += f"Function Summary: {summary.entry_functions.get(entry_name, 'N/A')}\n"
    #         prompt += f"Additional Info: {json.dumps(entry_info, indent=2)}\n"
    #         prompt += "Provide a detailed analysis."

    #         raw_response = self._ask(prompt)
    #         augmented_summary[entry_name] = raw_response

    #     return augmented_summary
