import requests
import json
import base64
from ecdsa import SigningKey, NIST256p
from datetime import datetime, timedelta, timezone

# ============================================
# 設定
# ============================================
BASE_URL = "http://localhost:52000"       # Local Catalog AuthZ API
PKR_BASE_URL = "http://localhost:60000"   # Public Key Registry API
ADMIN_ID = "admin001"

# ===== デバッグ用の秘密鍵 =====
PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP6X8oPiUZRjthKX9yHZPGyliWcH3uoxZ8FzPZduhRPHoAoGCCqGSM49
AwEHoUQDQgAE6+Lkl/VPSzT+oEB2XvOIf19S7tI5Ne3zDwW4+IXCoDypg2EYg6lT
UuXrw50xmyBB7fIFcImrEr3InxPHTCPSbw==
-----END EC PRIVATE KEY-----"""

sk = SigningKey.from_pem(PRIVATE_KEY_PEM)
public_key_pem = sk.get_verifying_key().to_pem().decode()

# ============================================
# 共通関数
# ============================================
def sign_message(private_key_pem: str, message: str) -> str:
    sk = SigningKey.from_pem(private_key_pem)
    sig = sk.sign(message.encode("utf-8"))
    return base64.b64encode(sig).decode("utf-8")

def iso_now_plus(minutes: int = 5) -> str:
    """現在時刻 + N分 の ISO8601文字列 (UTC, Z付き)"""
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

def pretty(res):
    print(f"\n[HTTP {res.status_code}]")
    try:
        print(json.dumps(res.json(), indent=2, ensure_ascii=False))
    except Exception:
        print(res.text)

# ============================================
# 0. 公開鍵登録 (PKR /add)
# ============================================
print("\n=== 0. Register public key (PKR /add) ===")
expire_time = iso_now_plus(5)
msg = ADMIN_ID + public_key_pem + expire_time
sig = sign_message(PRIVATE_KEY_PEM, msg)
res = requests.post(f"{PKR_BASE_URL}/add", json={
    "user_id": ADMIN_ID,
    "public_key": public_key_pem,
    "signature": sig,
    "expire_time": expire_time
})
pretty(res)


# ============================================
# 1. Reset（初期化）
# ============================================
print("\n=== 1. /reset ===")
res = requests.post(f"{BASE_URL}/reset")
pretty(res)


# ============================================
# 2. データ登録（署名付き）
# ============================================
print("\n=== 2. /add_data (with signature) ===")
expire_time = iso_now_plus(5)
data_items = [
    {
        "data_id": "sensor001",
        "description": "Temperature sensor dataset",
        "admin_id": ADMIN_ID,
        "endpoint": "http://edge.local/sensor001", 
    },
    {
        "data_id": "camera002",
        "description": "Surveillance camera dataset",
        "admin_id": ADMIN_ID,
        "endpoint": "http://edge.local/camera002", 
    }
]

for item in data_items:
    expire_time = iso_now_plus(5)
    msg = item["data_id"] + item["description"] + item["admin_id"] + item["endpoint"] + expire_time
    sig = sign_message(PRIVATE_KEY_PEM, msg)

    payload = {
        "data_id": item["data_id"],
        "description": item["description"],
        "admin_id": item["admin_id"],
        "endpoint": item["endpoint"],
        "expire_time": expire_time,
        "signature": sig,
    }
    res = requests.post(f"{BASE_URL}/add_data", json=payload)
    pretty(res)


# ============================================
# 3. 認可登録（署名付き）
# ============================================
print("\n=== 3. /add_authz (with signature) ===")
now = datetime.now(timezone.utc)
expire_soon = (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
expire_later = (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")

authz_items = [
    {"data_id": "sensor001", "access_grantee_id": "userA", "expire_at": expire_later},
    {"data_id": "sensor001", "access_grantee_id": "userB", "expire_at": expire_soon},
    {"data_id": "camera002", "access_grantee_id": "userC", "expire_at": expire_later},
]

for item in authz_items:
    expire_time = iso_now_plus(5)
    msg = item["data_id"] + item["access_grantee_id"] + item["expire_at"] + expire_time
    sig = sign_message(PRIVATE_KEY_PEM, msg)

    payload = {
        "data_id": item["data_id"],
        "access_grantee_id": item["access_grantee_id"],
        "expire_at": item["expire_at"],
        "expire_time": expire_time,
        "signature": sig,
    }
    res = requests.post(f"{BASE_URL}/add_authz", json=payload)
    pretty(res)


# ============================================
# 4. データ取得（署名付き）
# ============================================
print("\n=== 4. /get_data/sensor001 (署名付き) ===")
expire_time = iso_now_plus(5)
signature = sign_message(PRIVATE_KEY_PEM, expire_time)
payload = {
    "admin_id": ADMIN_ID,
    "expire_time": expire_time,
    "signature": signature
}
res = requests.post(f"{BASE_URL}/get_data/sensor001", json=payload)
pretty(res)


# ============================================
# 5. 認可取得（署名付き）
# ============================================
print("\n=== 5. /get_authz/sensor001 (署名付き) ===")
expire_time = iso_now_plus(5)
signature = sign_message(PRIVATE_KEY_PEM, expire_time)
payload = {
    "admin_id": ADMIN_ID,
    "expire_time": expire_time,
    "signature": signature
}
res = requests.post(f"{BASE_URL}/get_authz/sensor001", json=payload)
pretty(res)


# ============================================
# 6. データ削除（署名付き）
# ============================================
print("\n=== 6. /delete_data/sensor001 (署名付き) ===")
expire_time = iso_now_plus(5)
msg = "sensor001" + data_items[0]["description"] + data_items[0]["admin_id"] + data_items[0]["endpoint"] + expire_time
sig = sign_message(PRIVATE_KEY_PEM, msg)
res = requests.post(f"{BASE_URL}/delete_data/sensor001", json={
    "description": data_items[0]["description"],
    "admin_id": data_items[0]["admin_id"],
    "endpoint": data_items[0]["endpoint"],
    "expire_time": expire_time,
    "signature": sig
})
pretty(res)


# ============================================
# 7. 認可削除（署名付き）
# ============================================
print("\n=== 7. /delete_authz/camera002/userC (署名付き) ===")
expire_time = iso_now_plus(5)
msg = "camera002" + "userC" + expire_time
sig = sign_message(PRIVATE_KEY_PEM, msg)
res = requests.post(f"{BASE_URL}/delete_authz/camera002/userC", json={
    "expire_time": expire_time,
    "signature": sig
})
pretty(res)


# ============================================
# 8. debug_all（状態確認）
# ============================================
print("\n=== 8. /debug_all ===")
res = requests.get(f"{BASE_URL}/debug_all")
pretty(res)


# ============================================
# 9. データ削除（camera002）署名付き
# ============================================
print("\n=== 9. /delete_data/camera002 (署名付き) ===")
expire_time = iso_now_plus(5)
msg = "camera002" + data_items[1]["description"] + data_items[1]["admin_id"] + data_items[1]["endpoint"] + expire_time
sig = sign_message(PRIVATE_KEY_PEM, msg)
res = requests.post(f"{BASE_URL}/delete_data/camera002", json={
    "description": data_items[1]["description"],
    "admin_id": data_items[1]["admin_id"],
    "endpoint": data_items[1]["endpoint"],
    "expire_time": expire_time,
    "signature": sig
})
pretty(res)


# ============================================
# 10. debug_all（最終状態確認）
# ============================================
print("\n=== 10. /debug_all (final) ===")
res = requests.get(f"{BASE_URL}/debug_all")
pretty(res)
