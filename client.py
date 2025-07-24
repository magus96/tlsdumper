from curl_cffi import requests

URL = f"https://localhost:8443/?version=browser_name_version_number"

print(f"[*] Sending request to {URL}")

try:
    # We use verify=False because the server is using a self-signed certificate.
    response = requests.get(URL, verify=False, impersonate="safari18_4_ios")
    
    print(f"[+] Request sent successfully.")
    print(f"    Status Code: {response.status_code}")
    print(f"    Server Response: {response.text.strip()}")
    print("\n[*] Check the server's console output to see capture details.")

except requests.exceptions.SSLError as e:
    print(f"[!] SSL Error. This is expected if you don't use 'verify=False' with a self-signed cert.")
    print(f"    Details: {e}")
except requests.exceptions.ConnectionError as e:
    print(f"[!] Connection Error. Is the server running?")
    print(f"    Command: python3 main.py")
    print(f"    Details: {e}")

