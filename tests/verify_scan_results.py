import asyncio
import httpx
import json

async def test_scan():
    url = "http://localhost:8000/scan"
    # Use a narrow path to speed up the process
    payload = {"binary_scan_paths": ["/bin"]} 
    
    print(f"Sending request to {url}...")
    try:
        # Increase timeout significantly for NVD API calls
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, json=payload)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                # Save result to file for manual inspection
                with open("scan_result.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                print("\n[+] Success! Result saved to 'scan_result.json'")
                
                daemons = data.get("daemons", [])
                binaries = data.get("binaries", [])
                print(f"Found: {len(daemons)} daemons, {len(binaries)} binaries")
                
                found_score = False
                for d in daemons:
                    for v in d.get("vulnerabilities", []):
                        if v.get("cvss_score") is not None:
                            print(f"Check: Found CVSS score {v.get('cvss_score')} for {d.get('description')}")
                            found_score = True
                            break
                    if found_score: break
                
                if not found_score:
                    print("\n[!] No CVSS scores found in the response. Please check NVD API key or target version.")
                    
            else:
                print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == '__main__':
    asyncio.run(test_scan())
