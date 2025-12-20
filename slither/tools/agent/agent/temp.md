请根据我的需求为我的智能合约审计agent调用LLM提供合适的英文prompt：

任务，首先分析存在漏洞的代码和漏洞描述，然后结合调用链代码及状态变量信息
为所有漏洞生成相应的PoC
输出格式json，一个包含多个PoC的列表，每个PoC包含以下内容
title:string
severity: high/medium/low
confidence：flort in 0-1
vul_code_snippet: string
vul_description: string
Poc: string
Expexted result: string
remedation: string

提供的信息有

    vul_code: str,包含漏洞的智能合约函数代码
    vul_info: list[str],包含多条漏洞描述
    call_chain: list[str],从合约入口点到包含漏洞的函数的调用路径
    state_vars: dict[str, str],合约状态变量定义
