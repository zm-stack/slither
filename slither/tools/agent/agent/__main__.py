import argparse
from crytic_compile import cryticparser
from slither import Slither
from slither.tools.agent.llm_security_audit import CallGraphAnalyzer
from slither.tools.agent.graph_operation import (
    build_graphs, get_entry_points)

def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the agent.
    """
    parser = argparse.ArgumentParser(
        description="Security audit driven by an LLM-based agent",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    audit = subparsers.add_parser("audit",
        help="Audit a Solidity contract file/directory/address)"
    )
    audit.add_argument("contract",
        help="Path to Solidity file / directory OR contract address"
    )
    cryticparser.init(audit)

    learn = subparsers.add_parser("learn",
        help="Run audit + compare results to a vulnerable contract"
    )
    learn.add_argument("contract",
        help="Path to Solidity file / directory OR contract address"
    )
    learn.add_argument("vul_file",
        help="A JSON/TXT file containing known vulnerabilities"
    )
    cryticparser.init(learn)

    return parser.parse_args()

def main() -> None:
    # ---------- Build Slither object ----------
    args = parse_args()
    slither = Slither(args.contract, **vars(args))

    # ---------- Build call graphs ----------
    entry_points = get_entry_points(slither)
    print(f"### Discovered {len(entry_points)} entry points")
    graphs = build_graphs(entry_points)
    print(f"### Built {len(graphs)} call graphs")

    # ---------- Run analysis ----------
    for graph in graphs:
        analyzer = CallGraphAnalyzer(graph)
        # First analyze the entry point itself
        analyzer.analyze_entry_point()
        # Then DFS over the call graph from the entry point
        analyzer.dfs(graph.entry_point)
        graph.save()

    # ----------- learning mode extra step -----------
    if args.mode == "learn":
        print("### Learning mode enabled")
        print(f"### Comparing result with file: {args.vul_file}")

        # Example placeholder
        with open(args.vul_file, "r") as f:
            vul_data = f.read()
        print("### Loaded vulnerability data, ready for comparison")

if __name__ == "__main__":
    main()
