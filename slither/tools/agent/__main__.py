'''
【ACInf】用于智能合约项目权限推理与漏洞检测的复合Agent
- config_agent: 智能合约权限配置推理
- infer_agent: 函数继承权限与上下文权限推理
- defect_agent: 漏洞检测与PoC生成

依赖：
- openai API
- slither静态分析工具

原理
1. 合约建模：基于slithIR将合约按照调用链建立有向图
2. 权限摘要：定位主合约，获取权限配置信息
3. 复杂评估：代表扁平化，获取复杂度信息，包括
    定性：业务类型描述
    定量：继承深度/token数，函数数（包括modifier）/状态数/调用数
4. 初步规划：根据复杂度选择不同的工作流
    4.1 短合约提供完整代码进行分析；
    4.2 长合约通过上下文工程进行拆分多步分析。
    划分标准：由LLM根据记忆+定性定量描述自行决定
        反馈调节：根据执行漏报/误报行程记忆指导分类
5. 权限推理：从调用点出发沿调用方向，结合记忆进行权限分析
    入口函数单独分析
    之后BFS：权限继承与合取，循环处理
6. 攻击推理：从调用点出发沿调用方向，结合记忆进行漏洞检测
    首先分析权限配置（状态变量）
    之后DFS：提取工具路径，循环处理
7. 自我学习：形成并优化记忆
'''
# 测试项：
# （1）函数摘要中是否包括接口和继承的抽象合约定义

from slither.slither import Slither
from slither.tools.agent.config import parse_args
from slither.tools.agent.contract_modeling import (get_contract_models)

def main() -> None:
    args = parse_args()

    # Build Slither object based on the input contracts
    slither = Slither(args.contract, **vars(args))

    # (1) contract modeling
    contract_models = get_contract_models(slither)
    for model in contract_models:
        print(model)

    # llm = LLM(client)
    # for irc in ircs:
    #     cname = irc.name
    #     version = get_sol_version(slither, cname)
    #     # Analyze contract summary
    #     # output = llm.analyze_contract_summary(irc)
    #     output = {'business': 'Decentralized exchange enabling ERC20 order-book trading (Rubicon Market).', 'role_capability_resource': [{'role': 'owner/authorized', 'operation': 'set fees, fee recipients, min sell amounts, and halt market operations', 'resource': 'market configuration (feeBPS, MAKER_FEE_SLOT, feeTo, stopped, _dust)'}, {'role': 'market participant', 'operation': 'create, modify, cancel, and match offers including batch operations', 'resource': 'order book entries (offers, matching engine data structures)'}], 'access_control_state': ['owner', 'locked', 'matchingEnabled', 'stopped']}
    #     # Analyze access control config security
    #     for sv in output.get("access_control_state", []):
    #         funcs = get_funcs_rw_state(slither, cname, sv)
    #         report_text = llm.analyze_ac_config(
    #             cname, version, output, sv, funcs)
    #         report(f"AC Config Audit:\n{report_text}")

    #     # Infer access control from each entry point
    #     aug_ic = llm.infer_access_control(output, irc)

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




# def report(text: str, file: str="output/report.txt") -> None:
#     """Audit report in human-readable format."""
#     os.makedirs(os.path.dirname(file), exist_ok=True)
#     with open(file, "a", encoding="utf-8") as f:
#         f.write("=" * 80 + "\n")
#         f.write(text)
#         f.write("\n\n")