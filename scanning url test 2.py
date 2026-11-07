import base64
import time
import requests





# 1. Paste your actual key here
API_KEY = "936fc7949586d85f5987af4896a73dda7a47e6bf9862bfdc90e8da41141dfc43"
HEADERS = {"x-apikey": API_KEY, "accept": "application/json"}

def get_url_id(url: str) -> str:
    """Generates a perfect VirusTotal API v3 URL identifier."""
    clean_url = url.strip()
    encoded = base64.urlsafe_b64encode(clean_url.encode("utf-8"))
    return encoded.decode("utf-8").rstrip("=")

def scan_url(target_url: str):
    url_id = get_url_id(target_url)
    
    # 100% EXPLICIT AND HARDCODED PATH
    report_endpoint = "https://www.virustotal.com/api/v3/urls/" + url_id
    
    print(f"Checking: {target_url}")
    
    try:
        response = requests.get(report_endpoint, headers=HEADERS)
        
        # Scenario A: The URL exists in the database
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            print(f"\nResults for {target_url}:")
            print(f"➡ Malicious: {stats['malicious']}")
            print(f"➡ Suspicious: {stats['suspicious']}")
            print(f"➡ Harmless: {stats['harmless']}\n")
            
        # Scenario B: 404 - Not Found. Trigger automatic submission!
        elif response.status_code == 404:
            print("⚠ URL not found in database. Automatically submitting it now...")
            
            # 100% EXPLICIT AND HARDCODED SUBMISSION PATH
            submit_endpoint = "https://www.virustotal.com/api/v3/urls/"
            
            submit_response = requests.post(submit_endpoint, headers=HEADERS, data={"url": target_url})
            
            if submit_response.status_code == 200:
                print("🚀 Successfully submitted! Waiting 15 seconds for analysis...")
                time.sleep(15)
                print("🔄 Retrying report fetch...\n")
                return scan_url(target_url)
            else:
                print(f"❌ Failed to submit URL: {submit_response.status_code} - {submit_response.text}")
                
        # Scenario C: Something else went wrong (e.g., Wrong API key)
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Network Error: Make sure your internet is working. Code: {e}")

if __name__ == "__main__":
    scan_url("https://www.fbi.gov/how-we-can-help-you/common-frauds-and-scams/spoofing-and-phishing")
