import argparse
import logging

from crytic_compile import cryticparser

from slither import Slither
from slither.tools.agent.graph_operate import build_graphs, get_entry_points
logging.basicConfig()
logging.getLogger("Slither").setLevel(logging.INFO)

# 输入：文件路径/链上合约地址
# 1. 构造并运行slither命令，转为slither对象，生成argumented CFGs
# 2. 构造context和prompt，调用LLM，DFS CFGs丰富权限信息，识别漏洞
# 		LLM返回权限信息，用于丰富CFGs
# 		LLM返回格式化漏洞信息，包括是否存在，类型、描述、严重程度
# 		    如果存在漏洞，则返回调用链及漏洞信息，构成一条漏洞报告
# 3. 构造context和prompt，调用LLM，针对报告生成PoC，提供可信度评分

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security audit driven by LLM agent",
        usage=("slither-agent <source file or deployment address>"),
    )
    parser.add_argument(
        "contract",
        help="contract address if verified on etherscan"
        " or directory/filename for local contract."
    )
    cryticparser.init(parser)
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    target = args.contract
    slither = Slither(target, **vars(args))
    entry_points = get_entry_points(slither)
    graphs = build_graphs(entry_points)


if __name__ == "__main__":
    main()
