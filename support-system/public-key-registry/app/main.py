from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from datetime import datetime, timezone
import base64
import time

# =====================================
# 設定
# =====================================
DATABASE_URL = "postgresql://user:password@db:5432/public_key_registry"

# DB接続待ち
for _ in range(10):
    try:
        engine = create_engine(DATABASE_URL)
        engine.connect()
        break
    except Exception:
        print("Waiting for PostgreSQL...")
        time.sleep(3)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =====================================
# DBモデル
# =====================================
class PublicKey(Base):
    __tablename__ = "public_keys"
    user_id = Column(String, primary_key=True, index=True)
    public_key = Column(String, nullable=False)  # PEM形式
    registered_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# =====================================
# FastAPI初期化
# =====================================
app = FastAPI(title="Public Key Registry (PEM+Base64)")

# =====================================
# スキーマ定義
# =====================================
class RegisterRequest(BaseModel):
    user_id: str
    public_key: str  # PEM形式
    signature: str   # Base64署名
    expire_time: str # UNIX時刻(署名の有効期限)

class DeleteRequest(BaseModel):
    user_id: str
    public_key: str
    signature: str
    expire_time: str # UNIX時刻(署名の有効期限)

# =====================================
# 共通関数
# =====================================
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

def check_expire_time(expire_time_str: str):
    """
    ISO8601形式のexpire_time文字列が現在時刻を過ぎていないか確認。
    例: "2025-11-02T21:45:00Z"
    """
    try:
        expire_dt = datetime.fromisoformat(expire_time_str.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid expire_time format")

    now_dt = datetime.now(timezone.utc)
    if now_dt > expire_dt:
        raise HTTPException(status_code=400, detail="Signature expired")
    else:
        return True

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =====================================
# API
# =====================================
@app.post("/add")
def add_key(req: RegisterRequest):
    db = next(get_db())
    msg = req.user_id + req.public_key + req.expire_time
    if not check_expire_time(req.expire_time):
        raise HTTPException(status_code=400, detail="Expired signature")

    if not verify_signature(req.public_key, msg, req.signature):
        raise HTTPException(status_code=400, detail="Invalid signature")

    if db.query(PublicKey).filter_by(user_id=req.user_id).first():
        raise HTTPException(status_code=409, detail="UserID already registered")

    new_key = PublicKey(
        user_id=req.user_id,
        public_key=req.public_key,
        registered_at=datetime.utcnow()
    )
    db.add(new_key)
    db.commit()
    return {"message": f"Key for '{req.user_id}' registered successfully."}


@app.get("/get/{user_id}")
def get_key(user_id: str):
    db = next(get_db())
    key = db.query(PublicKey).filter_by(user_id=user_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return {
        "user_id": key.user_id,
        "public_key": key.public_key,
        "registered_at": key.registered_at.isoformat() if key.registered_at else None
    }


@app.delete("/delete")
def delete_key(req: DeleteRequest):
    db = next(get_db())
    msg = req.user_id + req.public_key + req.expire_time
    if not check_expire_time(req.expire_time):
        raise HTTPException(status_code=400, detail="Expired signature")
    
    if not verify_signature(req.public_key, msg, req.signature):
        raise HTTPException(status_code=400, detail="Invalid signature")

    key = db.query(PublicKey).filter_by(user_id=req.user_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    db.delete(key)
    db.commit()
    return {"message": f"Key for '{req.user_id}' deleted successfully."}


@app.get("/list")
def list_keys():
    db = next(get_db())
    keys = db.query(PublicKey).all()
    return [
        {
            "user_id": k.user_id,
            "public_key": k.public_key,
            "registered_at": k.registered_at.isoformat() if k.registered_at else None
        }
        for k in keys
    ]


@app.delete("/delete_all")
def delete_all_keys():
    db = next(get_db())
    count = db.query(PublicKey).delete()
    db.commit()
    return {"message": f"All {count} keys deleted successfully."}
