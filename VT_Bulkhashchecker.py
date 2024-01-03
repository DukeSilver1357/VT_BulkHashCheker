import requests
import time
import sys
import pandas as pd
from tqdm import tqdm
import urllib3
urllib3.disable_warnings()


def vt_bulk_hash_check(apikey: str, hashes: pd.DataFrame) -> pd.DataFrame:
    pbar = tqdm(total=len(hashes.columns), desc="Bulk lookup started...")
    hash_results = {}

    for hashn in hashes:
        pbar.display()
        url = "https://www.virustotal.com/api/v3/files/"
        headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        response = requests.get(url + hashn, headers=headers, timeout=120, verify=False)
        pbar.update(1)
        if response.status_code != 200:
            hash_results[hashn] = {}
            hash_results[hashn]['vt_results'] = False
        else:
            result = response.json()
            hash_results[hashn] = {}
            hash_results[hashn]['vt_results'] = True
            hash_results[hashn]['file_name'] = result['data']['attributes']['names'][0]
            hash_results[hashn]['file_type'] = result['data']['attributes']['type_description']
            hash_results[hashn]['detected_suspicious'] = result['data']['attributes']['last_analysis_stats'][
                'suspicious']
            hash_results[hashn]['detected_malicious'] = result['data']['attributes']['last_analysis_stats']['malicious']
            hash_results[hashn]['threat_label'] = result['data']['attributes']['popular_threat_classification'][
                'suggested_threat_label']
            hash_results[hashn]['tags'] = str(result['data']['attributes']['tags'])
        time.sleep(1)
    return pd.DataFrame.from_dict(hash_results, orient='index')


if __name__ == "__main__":
    results_df = vt_bulk_hash_check(apikey=sys.argv[1],
                                    hashes=pd.read_csv(sys.argv[2]))
    results_df.to_excel(sys.argv[3])
