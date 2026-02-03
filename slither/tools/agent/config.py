import argparse
from openai import OpenAI
from crytic_compile import cryticparser

# Configure OpenAI LLM client
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key="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")

# Parse command-line arguments
def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the agent.
    """
    parser = argparse.ArgumentParser(
        description="ACInf: An Agent that Reasons" \
        " About Contract Access Control issues" \
        " like a Human Auditor",
    )
    subparsers = parser.add_subparsers(
        dest="mode", required=True)

    audit = subparsers.add_parser("audit", help="Audit mode")
    audit.add_argument("contract",
        help="On-chain address or directory/file path"
    )
    cryticparser.init(audit)

    learn = subparsers.add_parser("learn",
        help="Audit + self-evolve learning"
    )
    learn.add_argument("contract",
        help="On-chain address or directory/file path"
    )
    learn.add_argument("vul_file",
        help="Path to vulnerability data file for learning"
    )
    cryticparser.init(learn)

    return parser.parse_args()