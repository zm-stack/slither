# OrAudit

## Introduction

This repository provides **OrAudit**, the tool introduced in paper "Towards Secure Oracle Usage: Understanding and Detecting the Vulnerabilities in Oracle Contracts on the Blockchain".

OrAudit is a static analysis tool designed to detect Oracle Consumer Contract Vulnerabilities (OCCVs). It is an extension built on top of [Slither](https://crytic.github.io/slither/slither.html), a widely-used static analysis framework for Solidity.

Specifically, OrAudit extends Slither by implementing three custom detectors:
- [oracle-data-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_data_check.py)
- [oracle-interface-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_interface_check.py)
- [oracle-protection-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_protection_check.py)

These detectors are designed to detect the following types of vulnerabilities:

| Phase            | ID       | Vulnerability                          |
|-----------------|----------|----------------------------------------|
| Request Handling | OCCV-1  | Missing request cancellation interface |
|                  | OCCV-2  | Missing withdrawal after payment        |
|                  | OCCV-3  | Missing request access control          |
|                  | OCCV-4  | Missing request circuit breaker         |
|                  | OCCV-5  | Missing request upgrade mechanism       |
|                  | OCCV-6  | Improper request error handling         |
|                  | OCCV-7  | Revert in oracle request fulfillment   |
|                  | OCCV-8  | Insecure oracle interface usage         |
|                  | OCCV-9  | Excessive request gas usage             |
| Data Processing  | OCCV-10 | Insufficient data availability checks  |
|                  | OCCV-11 | Insufficient data integrity checks     |
|                  | OCCV-12 | Improper modification of oracle data   |


For detailed descriptions of these vulnerabilities, please refer to the Section.4 of the paper "Towards Secure Oracle Usage: Understanding and Detecting the Vulnerabilities in Oracle Contracts on the Blockchain".

## Usage

### Applicability Scope
Currently, OrAudit supports the detection of source code for oracle consumer contracts from four major oracle providers. The supported oracle services are as follows:

Index | Provider | Service | Dependency
--- | --- | --- | ---
1|Chainlink|[Data Feed](https://docs.chain.link/data-feeds)| AggregatorV3Interface, AccessControlledOffchainAggregator
2|Chainlink|[Data Stream](https://docs.chain.link/data-streams)|StreamsLookupCompatibleInterface
3|Chainlink|[Any API](https://docs.chain.link/any-api/introduction)|ChainlinkClient
4|Chainlink|[Functions](https://docs.chain.link/chainlink-functions)|FunctionsClient
5|Chainlink|[VRF](https://docs.chain.link/vrf)|VRFConsumerBaseV2, VRFV2WrapperConsumerBase, VRFConsumerBaseV2Plus, VRFV2PlusWrapperConsumerBase
6|Pyth|[Data Feed](https://docs.pyth.network/price-feeds)|IPyth
7|Pyth|[Data Stream](https://docs.pyth.network/lazer)|PythLazer
8|Pyth|[VRF](https://docs.pyth.network/entropy)|IEntropyConsumer
9|Chronicle|[Data Feed](https://docs.chroniclelabs.org/Developers/start)|IChronicle
10|Redstone|[Data Feed](https://docs.redstone.finance/docs/dapps/redstone-pull/)|RedstoneConsumerBase

### Dependency
Slither requires Python 3.8+ and [solc](https://github.com/ethereum/solidity/), the Solidity compiler. We recommend using [solc-select](https://github.com/crytic/solc-select) to conveniently switch between solc versions according to the detected contracts.

### Installation

After cloning the repository, execute the following commands in the root directory of the repository:
```bash
python3 -m pip install .
```

### Execution Command

For local contracts, please use the following command:
```console
slither --detect oracle-data-check,oracle-interface-check,oracle-protection-check YourContractPath
```

For deployed contracts on Etherscan, please use the following command:
```console
slither --detect oracle-data-check,oracle-interface-check,oracle-protection-check ContractAddreess --etherscan-apikey YourApiKey
```
You can obtain YourApiKey by visiting https://etherscan.io/apidashboard. For contracts deployed on other blockchains, please refer to [Etherscan options](https://github.com/crytic/crytic-compile/wiki/Configuration#etherscan-options) and replace with the corresponding APIKEY.

## Dataset

The dataset directory contains all datasets referenced in this paper, including raw data, intermediate/process data, and result data.

- **Dataset_120.xlsx**: The experimental dataset containing 120 sampled contracts, manually annotated with OCCVs.
- **EvaluationResults.xlsx**: Contains all experimental process data, including: basic information of experimental dataset, statistics on analysis success rates, statistics on analysis time consumption, data used for calculating accuracy and recall.
- **analyze.py**: Script to run OrAudit on a specified `contracts.xlsx` file and record the analysis results.  
- **analyze_compare.py**: Script to run Slither's built-in detectors on `Dataset_120.xlsx` and record the analysis results.  
- **compare_summary.xlsx**: Records the OCCVs detected by Slither's built-in detectors for the contract addresses listed in `Dataset_120.xlsx`.  
- **compare_output.log**: Contains the complete output generated by Slither's built-in detectors for the contract addresses listed in `Dataset_120.xlsx`.


### `dataset/empirical_study`

OracleAttacks.xlsx records the results of the empirical study on oracle attacks described in Section 3 of the paper. It contains data on 52 attacks with the following columns:

- **Time**: The timestamp of the attack.  
- **Program**: The affected  program.  
- **Type**: The category of the attack.  
- **Loss**: The financial loss caused by the attack.  
- **Cause**: The underlying cause.  
- **Description**: A brief description of the attack.  
- **Recommendation**: Suggested mitigation or countermeasures.  
- **Reference**: Source or reference for the attack information.

### `dataset/contracts`

This directory contains datasets for 13 oracle services and a crawling script. Each dataset includes the following files:

- **HTML files**: Raw pages retrieved from Etherscan.  
- **contracts.xlsx**: Contract data extracted from the HTML files by dataset/contracts/get_address.py.  
- **analysis_summary.xlsx**: Records the OCCVs detected by OrAudit for the contract addresses listed in `contracts.xlsx`.  
- **output/**: Contains the complete output generated by OrAudit when analyzing the contract addresses in `contracts.xlsx`.

## Experiment Replication

First, please follow the instructions to install OrAudit and solc-select.

Next, run the following command to perform OCCV detection on the specified set of contracts (In analyze.py, replace the INPUT_FILE with the path to your target file) before running the script.):

```
python3 dataset/analyze.py
```
The detection results will be saved in the OUTPUT_LOG, SUMMARY_FILE.


## License

OrAudit, built on top of [Slither](https://crytic.github.io/slither/slither.html), also follows the AGPLv3 license.