import requests
import json
import base64
from datetime import datetime, timedelta, timezone
import time
from ecdsa import SigningKey, NIST256p, VerifyingKey, BadSignatureError

PKR_BASE_URL = "http://localhost:60000"
USER_ID = "userA"

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

def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    """PEM公開鍵 + Base64署名で検証"""
    try:
        vk = VerifyingKey.from_pem(public_key_pem)
        signature = base64.b64decode(signature_b64)
        vk.verify(signature, message.encode("utf-8"))
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        print("[ERROR verify_signature]", e)
        return False

def iso_now_plus(minutes: int = 5) -> str:
    """現在時刻 + N分 の ISO8601文字列 (UTC, Z付き)"""
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

        
def wait_for_server(base_url, name):
    for i in range(10):
        try:
            r = requests.get(f"{base_url}/docs")
            if r.status_code == 200:
                print(f"{name} server ready at {base_url}")
                return
        except Exception:
            pass
        print(f"Waiting for {name} ... ({i+1}/10)")
        time.sleep(2)
    raise Exception(f"{name} not ready.")

# ===== テスト開始 =====
wait_for_server(PKR_BASE_URL, "Public-Key-Registry")

# === 1. 公開鍵登録 ===
print("\n=== 1. /add ===")
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

# === 2. 取得 ===
print("\n=== 2. /get/{user_id} ===")
res = requests.get(f"{PKR_BASE_URL}/get/{USER_ID}")
pretty(res)

# === 2.1. 取得した公開鍵でデジタル署名の検証 ===
print("\n=== 2.1. Verify fetched public_key_data ===")
data = res.json()
fetched_pubkey_pem = data.get("public_key")
verified = verify_signature(fetched_pubkey_pem, msg, sig)
print(fetched_pubkey_pem)

if verified:
    print("Signature verification successful.")
else:
    print("Signature verification failed.")
            

# === 3. 一覧 ===
print("\n=== 3. /list ===")
res = requests.get(f"{PKR_BASE_URL}/list")
pretty(res)

# === 4. 削除 ===
print("\n=== 4. /delete ===")
expire_time = iso_now_plus(5)
msg_del = USER_ID + public_key_pem + expire_time
sig_del = sign_message(private_key_pem, msg_del)
res = requests.delete(f"{PKR_BASE_URL}/delete", json={
    "user_id": USER_ID,
    "public_key": public_key_pem,
    "signature": sig_del,
    "expire_time": expire_time
})
pretty(res)

# === 5. 削除確認 ===
print("\n=== 5. /get/{user_id} ===")
res = requests.get(f"{PKR_BASE_URL}/get/{USER_ID}")
print(res.status_code, res.text)

# === 6. 複数ユーザ登録 ===
print("\n=== 6. /add (multiple users) ===")
users = ["userB", "userC", "userD"]

for uid in users:
    expire_time = iso_now_plus(5)
    msg = uid + public_key_pem + expire_time
    sig = sign_message(private_key_pem, msg)
    res = requests.post(f"{PKR_BASE_URL}/add", json={
        "user_id": uid,
        "public_key": public_key_pem,
        "signature": sig,
        "expire_time": expire_time
    })
    print(f"[{uid}] → status {res.status_code}")
    pretty(res)

# === 7. /list (全ユーザ確認) ===
print("\n=== 7. /list ===")
res = requests.get(f"{PKR_BASE_URL}/list")
pretty(res)

# === 8. /delete_all ===
print("\n=== 8. /delete_all ===")
#res = requests.delete(f"{PKR_BASE_URL}/delete_all")
#pretty(res)

# === 9. /list (削除後確認) ===
print("\n=== 9. /list ===")
res = requests.get(f"{PKR_BASE_URL}/list")
pretty(res)

# === 10. 各ユーザ取得確認 ===
for uid in ["userA"] + users:
    print(f"\n=== 10. /get/{uid} ===")
    res = requests.get(f"{PKR_BASE_URL}/get/{uid}")
    print(res.status_code, res.text)
