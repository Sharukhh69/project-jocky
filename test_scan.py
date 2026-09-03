import urllib.request, json

payload = json.dumps({
    'case_id': 'TEST_CASE',
    'target_ip': '127.0.0.1',
    'target_port': 5000,
    'command': 'scan.files("D:/")'
}).encode('utf-8')

req = urllib.request.Request('http://127.0.0.1:8000/api/run', data=payload, headers={'Content-Type': 'application/json'})
res = urllib.request.urlopen(req)
data = json.loads(res.read().decode())

print("Scanned Path:", data.get("path"))
print("Total Items in D: drive:", data.get("count"))
for item in data.get("results", [])[:10]:
    print(f"  * [{ 'DIR ' if item.get('is_dir') else 'FILE'}] {item.get('name')} -> {item.get('path')}")
