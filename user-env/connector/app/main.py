from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from ecdsa import SigningKey, NIST256p
from datetime import datetime, timezone, timedelta
import os, json, base64, hashlib, requests

app = FastAPI(title="Connector API (PoC, SHA256 hash)")

USER_DIR = "./app/users"
KEY_DIR = "./app/keys"
os.makedirs(USER_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

security = HTTPBasic()
PUBLIC_KEY_REGISTRY_URL = os.getenv("PUBLIC_KEY_REGISTRY_URL", "http://host.docker.internal:60000")
FEDERATED_CATALOG_URL = os.getenv("FEDERATED_CATALOG_URL", "http://host.docker.internal:61000")

# ======== モデル ========
class RegisterRequest(BaseModel):
    user_id: str
    password_hash: str  # WebApp側で SHA256済み

class LoginRequest(BaseModel):
    user_id: str
    password_hash: str

# ======== 共通関数 ========
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

def verify_hashed_password(credentials: HTTPBasicCredentials = Depends(security)):
    user_id = credentials.username
    password_hash = credentials.password
    path = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=401, detail="User not found")
    with open(path) as f:
        data = json.load(f)
    if data["password_hash"] != password_hash:
        raise HTTPException(status_code=401, detail="Invalid password hash")
    return user_id
    

# ======== ユーザー登録 ========
@app.post("/register")
def register_user(req: RegisterRequest):
    user_path = os.path.join(USER_DIR, f"{req.user_id}.json")
    key_path = os.path.join(KEY_DIR, f"{req.user_id}.pem")

    if os.path.exists(user_path):
        raise HTTPException(status_code=409, detail="User already exists")

    # === ECDSA鍵生成 ===
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key
    private_key_pem = sk.to_pem().decode()
    public_key_pem = vk.to_pem().decode()

    expire_time = iso_now_plus(5)
    msg = req.user_id + public_key_pem + expire_time
    sig = sign_message(private_key_pem, msg)

    res = requests.post(f"{PUBLIC_KEY_REGISTRY_URL}/add", json={
        "user_id": req.user_id,
        "public_key": public_key_pem,
        "signature": sig,
        "expire_time": expire_time
    })
    pretty(res)

    with open(key_path, "w") as f:
        f.write(private_key_pem)

    user_info = {
        "user_id": req.user_id,
        "password_hash": req.password_hash,
        "public_key": public_key_pem,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    with open(user_path, "w") as f:
        json.dump(user_info, f, indent=2)

    return {"result": "ok", "message": f"User '{req.user_id}' registered successfully."}

# ======== ログイン ========
@app.post("/login")
def login_user(req: LoginRequest):
    user_path = os.path.join(USER_DIR, f"{req.user_id}.json")
    if not os.path.exists(user_path):
        raise HTTPException(status_code=404, detail="User not found")

    with open(user_path, "r") as f:
        user_data = json.load(f)

    if req.password_hash == user_data["password_hash"]:
        return {"result": "ok", "message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid password")

# ======== Basic認証付き API ========
@app.get("/users/{user_id}")
def get_user(user_id: str, _: str = Depends(verify_hashed_password)):
    user_path = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_path):
        raise HTTPException(status_code=404, detail="User not found")
    with open(user_path, "r") as f:
        return json.load(f)

@app.get("/debug_all_pk_users")
def get_all_users(_: str = Depends(verify_hashed_password)):
    res = requests.get(f"{PUBLIC_KEY_REGISTRY_URL}/list")
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail="Registry access error")
    return res.json()

@app.get("/search_by_keyword/{keyword}")
def search_by_keyword(keyword: str, _: str = Depends(verify_hashed_password)): 
    res = requests.get(f"{FEDERATED_CATALOG_URL}/search_by_keyword/{keyword}")
    if res.status_code != 200: 
        raise HTTPException(status_code=res.status_code, detail="Federated catalog access error")
    return res.json()
