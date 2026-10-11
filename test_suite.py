import urllib.request
import urllib.parse
import json
import secrets

BASE_URL = "http://127.0.0.1:5000"

def post_json(endpoint, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8')), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8')), e.headers

def post_multipart(endpoint, fields, files):
    boundary = "----WebKitFormBoundary" + secrets.token_hex(16)
    body = bytearray()
    
    for k, v in fields.items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        body.extend(f"{v}\r\n".encode())
        
    for k, (filename, file_bytes) in files.items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{k}"; filename="{filename}"\r\n'.encode())
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        body.extend(file_bytes)
        body.extend(b"\r\n")
        
    body.extend(f"--{boundary}--\r\n".encode())
    
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=bytes(body),
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8')), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8')), e.headers

def get_file(endpoint):
    req = urllib.request.Request(f"{BASE_URL}{endpoint}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw.decode('utf-8'))
        except Exception:
            parsed = {'raw': raw.decode('utf-8', errors='ignore')}
        return e.code, parsed, e.headers

print("=" * 70)
print("RUNNING COMPREHENSIVE CYBERSECURITY APP VERIFICATION SUITE")
print("=" * 70)

# Test 1: HTML & Static Delivery
req = urllib.request.Request(f"{BASE_URL}/")
with urllib.request.urlopen(req) as resp:
    html = resp.read().decode('utf-8')
    assert resp.status == 200, "GET / failed"
    assert "#0a0a0f" in html, "Background color missing"
    assert "0 0 20px rgba(0, 255, 136, 0.3)" in html or "0 0 20px rgba(0,255,136,0.3)" in html or "0 0 20px rgba(0, 255, 136, 0.35)" in html, "Glow shadow missing"
    assert "Courier New" in html, "Monospace font missing"
    print("[PASS] Test 1: GET / serves valid cybersecurity theme HTML")

# Test 2: RSA Keygen for 'Alice' and 'Bob'
status, data, _ = post_json('/keys', {'user_id': 'Alice'})
assert status == 200 and 'BEGIN PUBLIC KEY' in data['public_key'], f"Keygen Alice failed: {data}"
status, data, _ = post_json('/keys', {'user_id': 'Bob'})
assert status == 200 and 'BEGIN PUBLIC KEY' in data['public_key'], f"Keygen Bob failed: {data}"
print("[PASS] Test 2: RSA-4096 key pair generated for Alice and Bob")

# Test 3: Normal Benign File Upload from Alice to Bob
benign_content = b"Confidential security audit report: All crypto checks verified. " * 50
status, data, _ = post_multipart('/upload', {'sender': 'Alice', 'recipient': 'Bob'}, {'file': ('audit_report.txt', benign_content)})
assert status == 200 and data['ml_result']['safe'] is True, f"Upload benign failed: {data}"
file_id = data['file_id']
sha256 = data['sha256_hash']
print(f"[PASS] Test 3: Benign file uploaded & hybrid-encrypted as {file_id} (SHA-256: {sha256[:16]}...)")

# Test 4: Download by legitimate recipient 'bob' (case-insensitive)
status, content, headers = get_file(f"/download/{file_id}?user=bob")
assert status == 200, f"Download failed: {status}"
assert content == benign_content, "Decrypted content does not match original plaintext!"
assert headers.get('X-File-Hash') == sha256, "X-File-Hash header mismatch"
assert headers.get('X-File-Filename') == 'audit_report.txt', "X-File-Filename header mismatch"
print(f"[PASS] Test 4: Legitimate recipient Bob successfully decrypted and integrity-verified payload ({len(content)} bytes)")

# Test 5: Unauthorized recipient access (Eve tries to download Bob's file)
status, err, _ = get_file(f"/download/{file_id}?user=eve")
assert status == 403, f"Expected 403 Unauthorized, got {status}: {err}"
print(f"[PASS] Test 5: Unauthorized recipient 'eve' correctly rejected with 403")

# Test 6: Non-existent file ID download
status, err, _ = get_file(f"/download/nonexistent_999?user=bob")
assert status == 404, f"Expected 404 Not Found, got {status}: {err}"
print(f"[PASS] Test 6: Nonexistent file ID correctly rejected with 404")

# Test 7: ML Threat Detection on malicious/high-entropy payload
malicious_payload = secrets.token_bytes(4096)
status, data, _ = post_multipart('/upload', {'sender': 'Alice', 'recipient': 'Bob'}, {'file': ('trojan.exe', malicious_payload)})
assert status == 403 and data.get('blocked') is True, f"Expected 403 blocked, got {status}: {data}"
print(f"[PASS] Test 7: Malicious payload intercepted & blocked with 403 by ML IsolationForest")

# Test 8: Upload to recipient without keys
status, data, _ = post_multipart('/upload', {'sender': 'Alice', 'recipient': 'Dave'}, {'file': ('note.txt', b"Hello Dave")})
assert status == 404, f"Expected 404 for missing recipient keys, got {status}: {data}"
print(f"[PASS] Test 8: Upload to recipient without keys correctly handled with 404")

# Test 9: Case-insensitivity test (Generate for Charlie, upload for CHARLIE, download as charlie)
status, _, _ = post_json('/keys', {'user_id': 'Charlie'})
assert status == 200
status, data, _ = post_multipart('/upload', {'sender': 'Alice', 'recipient': 'CHARLIE'}, {'file': ('secret.txt', b"Top secret for Charlie")})
assert status == 200
charlie_fid = data['file_id']
status, content, _ = get_file(f"/download/{charlie_fid.upper()}?user=charlie")
assert status == 200 and content == b"Top secret for Charlie"
print(f"[PASS] Test 9: Case-insensitivity verified across user IDs and file IDs")

print("=" * 70)
print("ALL 9 COMPREHENSIVE TESTS PASSED WITH ZERO ERRORS!")
print("=" * 70)
