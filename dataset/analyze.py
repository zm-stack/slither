import subprocess
import pandas as pd
from tqdm import tqdm
import concurrent.futures
import os
import math

# ========== Configuration Section ==========
INDEX = 0
INPUT_FILE = 'contracts/AggregatorV3Interface/contracts.xlsx'
OUTPUT_LOG = 'contracts/AggregatorV3Interface/output.log'
SUMMARY_FILE = 'contracts/AggregatorV3Interface/analysis_summary.xlsx'
API_KEY = 'PI7D8QAHZQY9JFSJ8HH4WF87NAFRVN83VU'

BATCH_SIZE = 50        # Number of contracts to process per batch
MAX_WORKERS = 5        # Number of concurrent threads
# ==========================================

# Read the "Address" column from the Excel file
df = pd.read_excel(INPUT_FILE)
contract_addresses = df['Address'].dropna().tolist()
addresses_to_analyze = contract_addresses[INDEX:]

# Define vulnerability tags (OCCV1: ~ OCCV12:)
vuln_tags = [f"OCCV{i}:" for i in range(1, 13)]

def analyze_contract(contract_address):
    """Analyze a single smart contract and return both a result dictionary and raw log output."""
    COMMAND = (
        "slither --detect oracle-data-check,oracle-interface-check,oracle-protection-check "
        f"{contract_address} --etherscan-apikey {API_KEY}"
    )

    # Initialize the result dictionary for this contract
    result_dict = {"Address": contract_address}
    for tag in vuln_tags:
        result_dict[tag] = 0
    full_output = ""

    try:
        # Run Slither static analysis tool on the contract
        result = subprocess.run(COMMAND, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        full_output = result.stdout + result.stderr
    except Exception as e:
        full_output = str(e)

    # Check for each vulnerability tag in the output
    for tag in vuln_tags:
        if tag in full_output:
            result_dict[tag] = 1

    return result_dict, full_output


def process_batch(batch_addresses, batch_number):
    """Process a batch of contracts, return their results, and write detailed logs."""
    batch_results = []

    # Use a ThreadPoolExecutor for concurrent contract analysis
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_address = {executor.submit(analyze_contract, addr): addr for addr in batch_addresses}

        for future in tqdm(concurrent.futures.as_completed(future_to_address), total=len(batch_addresses),
                           desc=f"Batch {batch_number} analyzing"):
            addr = future_to_address[future]
            try:
                result_dict, log_output = future.result()
            except Exception as e:
                # If analysis fails, log an error and mark all vulnerabilities as 0
                result_dict = {"Address": addr}
                for tag in vuln_tags:
                    result_dict[tag] = 0
                log_output = f"Error analyzing {addr}: {e}"
            batch_results.append(result_dict)

            # Append analysis logs to the log file
            with open(OUTPUT_LOG, 'a', encoding='utf-8') as f:
                f.write(f"--- Contract Address: {addr} ---\n")
                f.write(log_output)
                f.write("\n" + "="*80 + "\n\n")

    return batch_results


# ===== Main Program =====
total_batches = math.ceil(len(addresses_to_analyze) / BATCH_SIZE)
written_rows = 0  # ✅ Track how many rows have been written to the summary file

for batch_number in range(total_batches):
    start_idx = batch_number * BATCH_SIZE
    end_idx = min(start_idx + BATCH_SIZE, len(addresses_to_analyze))
    batch_addresses = addresses_to_analyze[start_idx:end_idx]

    # Analyze the current batch
    batch_results = process_batch(batch_addresses, batch_number + 1)

    # Write results to the Excel summary file
    if not os.path.exists(SUMMARY_FILE):
        # First-time write with headers
        pd.DataFrame(batch_results).to_excel(SUMMARY_FILE, index=False)
        written_rows = len(batch_results)
    else:
        # ✅ Use the counter variable to append new rows without reloading the entire file
        with pd.ExcelWriter(SUMMARY_FILE, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
            pd.DataFrame(batch_results).to_excel(writer, index=False, header=False, startrow=written_rows + 1)
        written_rows += len(batch_results)

    print(f"✅ Batch {batch_number + 1} has been written to {SUMMARY_FILE}")

print(f"\n✅ All contract analyses are complete! Summary saved to: {SUMMARY_FILE}")
