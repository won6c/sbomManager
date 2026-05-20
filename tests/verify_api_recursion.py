
import asyncio
import httpx
import json

async def test_scan():
    url = "http://localhost:8000/scan"
    payload = {"binary_scan_paths": ["/bin"]}
    
    print(f"Sending request to {url}...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=30.0)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                print("Successfully received response!")
                # Print a small part of the response to verify structure
                data = response.json()
                print("Response Keys:", data.keys())
            else:
                print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == '__main__':
    asyncio.run(test_scan())
