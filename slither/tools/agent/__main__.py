
import os
from slither.slither import Slither
from slither.tools.agent.config import parse_args
from slither.tools.agent.config import client
from slither.tools.agent.llm_requests import LLM
from slither.tools.agent.contract_ir import (
    get_contract_irs, get_funcs_rw_state,
    get_sol_version
)

def report(text: str, file: str="output/report.txt") -> None:
    """Audit report in human-readable format."""
    os.makedirs(os.path.dirname(file), exist_ok=True)
    with open(file, "a", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(text)
        f.write("\n\n")

def main() -> None:
    # Build Slither object
    args = parse_args()
    slither = Slither(args.contract, **vars(args))

    # Build contract IR summaries
    ircs = get_contract_irs(slither)

    llm = LLM(client)
    for irc in ircs:
        cname = irc.name
        version = get_sol_version(slither, cname)
        # Analyze contract summary
        # output = llm.analyze_contract_summary(irc)
        output = {'business': 'Decentralized exchange enabling ERC20 order-book trading (Rubicon Market).', 'role_capability_resource': [{'role': 'owner/authorized', 'operation': 'set fees, fee recipients, min sell amounts, and halt market operations', 'resource': 'market configuration (feeBPS, MAKER_FEE_SLOT, feeTo, stopped, _dust)'}, {'role': 'market participant', 'operation': 'create, modify, cancel, and match offers including batch operations', 'resource': 'order book entries (offers, matching engine data structures)'}], 'access_control_state': ['owner', 'locked', 'matchingEnabled', 'stopped']}
        # Analyze access control config security
        for sv in output.get("access_control_state", []):
            funcs = get_funcs_rw_state(slither, cname, sv)
            report_text = llm.analyze_ac_config(
                cname, version, output, sv, funcs)
            report(f"AC Config Audit:\n{report_text}")

        # Infer access control from each entry point
        aug_ic = llm.infer_access_control(output, irc)

        # # Audit vulnerabilities based on aug_summary
        # reports = llm.audit_vulnerabilities(aug_summary, data)

        # if args.mode == "learn":
        #     with open(args.vul_file, "r") as f:
        #         vul_data = f.read()
        #         memory = llm.self_evolve(reports, vul_data, aug_summary)


    ## Analyze entries using state-based permission

    ## Analyze entries using context-based permission

    # Self evolve analysis

    # Save results

    # entry_points = get_entry_points(slither)
    # print(f"### Discovered {len(entry_points)} entry points")
    # graphs = build_graphs(entry_points)
    # print(f"### Built {len(graphs)} call graphs")

    # # ---------- Run analysis ----------
    # for graph in graphs:
    #     analyzer = CallGraphAnalyzer(graph)
    #     # First analyze the entry point itself
    #     analyzer.analyze_entry_point()
    #     # Then DFS over the call graph from the entry point
    #     analyzer.dfs(graph.entry_point)
    #     graph.save()

    # # ----------- learning mode extra step -----------
    # if args.mode == "learn":
    #     print("### Learning mode enabled")
    #     print(f"### Comparing result with file: {args.vul_file}")

    #     # Example placeholder
    #     with open(args.vul_file, "r") as f:
    #         vul_data = f.read()
    #     print("### Loaded vulnerability data, ready for comparison")

if __name__ == "__main__":
    main()




