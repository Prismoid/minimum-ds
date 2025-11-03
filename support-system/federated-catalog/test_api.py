import requests
import json
import base64
from ecdsa import SigningKey, NIST256p
from datetime import datetime, timedelta, timezone

PKR_BASE_URL = "http://localhost:60000"
FC_BASE_URL = "http://localhost:61000"
USER_ID = "user456"

# ===== デバック用の秘密鍵 =====
PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP6X8oPiUZRjthKX9yHZPGyliWcH3uoxZ8FzPZduhRPHoAoGCCqGSM49
AwEHoUQDQgAE6+Lkl/VPSzT+oEB2XvOIf19S7tI5Ne3zDwW4+IXCoDypg2EYg6lT
UuXrw50xmyBB7fIFcImrEr3InxPHTCPSbw==
-----END EC PRIVATE KEY-----"""

# ===== 鍵生成 =====
# sk = SigningKey.generate(curve=NIST256p) # 乱数で鍵生成
sk = SigningKey.from_pem(PRIVATE_KEY_PEM)
private_key_pem = sk.to_pem().decode()
public_key_pem = sk.get_verifying_key().to_pem().decode()

# ===== 共通関数 ===== 

def sign_message(private_key_pem: str, message: str) -> str:
    sk = SigningKey.from_pem(private_key_pem)
    sig = sk.sign(message.encode("utf-8"))
    return base64.b64encode(sig).decode("utf-8")

def pretty(res):
    try:
        print(json.dumps(res.json(), indent=2, ensure_ascii=False))
    except Exception:
        print(res.text)

def iso_now_plus(minutes: int = 5) -> str:
    """現在時刻 + N分 の ISO8601文字列 (UTC, Z付き)"""
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

# ===== 1. 公開鍵登録 (Public-Key-Registry) =====
print("\n=== 1. Register public key (PKR /add) ===")
expire_time = iso_now_plus(5)
msg = USER_ID + public_key_pem + expire_time
sig = sign_message(private_key_pem, msg)
res = requests.post(f"{PKR_BASE_URL}/add", json={
    "user_id": USER_ID,
    "public_key": public_key_pem,
    "signature": sig, 
    "expire_time": expire_time
})
pretty(res)


# ===== 2. Federated Catalog リセット =====
print("\n=== 2. Reset Federated Catalog (FC /reset) ===")
res = requests.post(f"{FC_BASE_URL}/reset")
pretty(res)

# ===== 3. データ登録 (Federated Catalog) =====
print("\n=== 3. Register data to Federated Catalog (FC /add) ===")
data = {
    "data_id": "edge_data_001",
    "user_id": USER_ID,
    "description": "IoT Edge device telemetry data for integration test",
    "endpoint": "http://edge-device.local/api/telemetry", 
    "expire_time": expire_time
}
msg_add = data["data_id"] + data["user_id"] + data["description"] + data["endpoint"] + expire_time
print("eroor check: ", msg_add)
sig_add = sign_message(private_key_pem, msg_add)
res = requests.post(f"{FC_BASE_URL}/add", json={**data, "signature": sig_add})
pretty(res)

# ===== 4. 登録確認 =====
print("\n=== 4. Confirm registration (FC /get/{data_id}) ===")
res = requests.get(f"{FC_BASE_URL}/get/{data['data_id']}")
pretty(res)



# ===== 5. 削除 =====
print("\n=== 5. Delete data (FC /delete/{data_id}) ===")
msg_del = data['data_id'] + data['user_id'] + expire_time
sig_del = sign_message(private_key_pem, msg_del)
res = requests.delete(f"{FC_BASE_URL}/delete/{data['data_id']}", json={
    "user_id": data["user_id"],
    "signature": sig_del, 
    "expire_time": expire_time
})
pretty(res)

# ===== 6. 削除確認 =====
print("\n=== 6. Confirm deletion (FC /get/data/{data_id}) ===")
res = requests.get(f"{FC_BASE_URL}/get/data/{data['data_id']}")
print(res.status_code, res.text)

# ===== 7. データを複数登録して検索テスト =====
print("\n=== 7. Register multiple data entries for search test ===")

entries = [
    {
        "data_id": "data_101",
        "description": "IoT temperature sensor in factory",
        "endpoint": "http://iot-factory.local/api/temp"
    },
    {
        "data_id": "data_102",
        "description": "Building environmental IoT data",
        "endpoint": "http://smart-building.local/api/env"
    },
    {
        "data_id": "data_103",
        "description": "Factory production line telemetry",
        "endpoint": "http://factory-line.local/api/metrics"
    }
]

for item in entries:
    expire_time = iso_now_plus(5)
    msg = item["data_id"] + USER_ID + item["description"] + item["endpoint"] + expire_time
    sig = sign_message(private_key_pem, msg)
    res = requests.post(f"{FC_BASE_URL}/add", json={
        "data_id": item["data_id"],
        "user_id": USER_ID,
        "description": item["description"],
        "endpoint": item["endpoint"],
        "signature": sig,
        "expire_time": expire_time
    })
    pretty(res)


# ===== 8. search_by_keyword の動作確認 =====
print("\n=== 8. Search by keyword (FC /search_by_keyword/IoT) ===")
keyword = "IoT"
res = requests.get(f"{FC_BASE_URL}/search_by_keyword/{keyword}")
pretty(res)


# ===== 9. search_by_user_id の動作確認 =====
print("\n=== 9. Search by user_id (FC /search_by_user_id/{USER_ID}) ===")
res = requests.get(f"{FC_BASE_URL}/search_by_user_id/{USER_ID}")
pretty(res)


# ===== 10. リセットして終了 =====
print("\n=== 10. Reset all catalog entries ===")
res = requests.post(f"{FC_BASE_URL}/reset")
pretty(res)

print("\n=== Test completed successfully. ===")
