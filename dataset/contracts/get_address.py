"""
Extract and process contract data from Etherscan HTML pages,
adding balance (Ether) and source code line count with batch saving.
"""

import os
import re
import time
import json
import requests
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup

# --------------------------------------------
# CONFIG
# --------------------------------------------
HTML_DIR = 'chainlink/FunctionsClient'
OUTPUT = 'chainlink/FunctionsClient/contracts.csv'
API_BASE = 'https://api.etherscan.io/v2/api'
API_KEY = 'PI7D8QAHZQY9JFSJ8HH4WF87NAFRVN83VU'
BATCH_SIZE = 20
SLEEP = 0.2

# --------------------------------------------
# HELPERS
# --------------------------------------------
def get_balance(address):
    """Fetch contract balance (in Ether)"""
    url = f"{API_BASE}?chainid=1&module=account&action=balance&address={address}&tag=latest&apikey={API_KEY}"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        wei = int(res.json().get("result", "0"))
        return wei / 1e18
    except Exception as e:
        print(f"[Balance Error] {address} - {e}")
        return None

def get_code_lines(address):
    """Fetch source code and count non-empty lines"""
    url = f"{API_BASE}?chainid=1&module=contract&action=getsourcecode&address={address}&apikey={API_KEY}"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        result = res.json().get("result", [])
        if not result or not isinstance(result, list):
            return 0
        source = result[0].get("SourceCode", "")
        if not source:
            return 0
        decoded = source.replace("\\n", "\n")
        return sum(1 for line in decoded.split("\n") if line.strip())
    except Exception as e:
        print(f"[Code Error] {address} - {e}")
        return None

def save_batch(batch_data):
    """Save a batch of records to CSV"""
    if not batch_data:
        return
    df = pd.DataFrame(batch_data)
    header = not os.path.exists(OUTPUT)
    df.to_csv(OUTPUT, mode='a', header=header, index=False, encoding='utf-8-sig')
    print(f"💾 Saved {len(batch_data)} records to {OUTPUT}")

# --------------------------------------------
# MAIN
# --------------------------------------------
html_files = [f for f in os.listdir(HTML_DIR) if f.endswith('.html')]
seen_addresses = set()
batch = []

for html_file in tqdm(html_files, desc="Processing HTML files"):
    try:
        with open(os.path.join(HTML_DIR, html_file), encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        cards = soup.find_all('div', class_='card')

        for card in tqdm(cards, desc=f"Parsing {html_file}", leave=False):
            try:
                addr_tag = card.find('a', href=True)
                if not addr_tag:
                    continue
                address = addr_tag.text.strip()
                if address in seen_addresses:
                    continue
                seen_addresses.add(address)

                # Parse info from HTML
                get_text = lambda icon: (card.find('i', class_=icon).find_next(string=True).strip()
                                         if card.find('i', class_=icon) else 'N/A')
                name = get_text('far fa-file-user text-muted')
                date = get_text('far fa-calendar-day text-muted')
                tx_text = (card.find('i', class_='far fa-exchange-alt text-muted')
                               .find_next('a').text.strip() if card.find('i', class_='far fa-exchange-alt text-muted') else 'N/A')
                txs = re.sub(r'\D', '', tx_text)

                # Fetch from API
                balance = get_balance(address)
                time.sleep(SLEEP)
                code_lines = get_code_lines(address)
                time.sleep(SLEEP)

                batch.append({
                    'Address': address,
                    'Name': name,
                    'Date': date,
                    'Transactions': txs,
                    'Balance(Ether)': balance,
                    'CodeLines': code_lines
                })

                if len(batch) >= BATCH_SIZE:
                    save_batch(batch)
                    batch.clear()

            except Exception as e:
                print(f"[Parse Error] {html_file} - {e}")

    except Exception as e:
        print(f"[File Error] {html_file} - {e}")

# Save remaining data
if batch:
    save_batch(batch)

print("✅ Done! All data processed and saved safely.")