from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from datetime import datetime, timezone
import base64
import time
import requests
import os

# =====================================
# 設定
# =====================================
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "db")
DB_NAME = os.getenv("POSTGRES_DB", "federated_catalog_db")
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}"

PUBLIC_KEY_REGISTRY_URL = os.getenv("PUBLIC_KEY_REGISTRY_URL", "http://host.docker.internal:60000")

# DB起動待ち
for _ in range(10):
    try:
        engine = create_engine(DATABASE_URL)
        engine.connect()
        print("Database connected successfully.")
        break
    except Exception:
        print("Waiting for PostgreSQL...")
        time.sleep(3)
else:
    raise Exception("Could not connect to PostgreSQL after 10 retries.")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =====================================
# DBモデル
# =====================================
class FederatedCatalog(Base):
    __tablename__ = "federated_catalog"
    data_id = Column(String, primary_key=True, index=True)
    user_id = Column(String, nullable=False)
    description = Column(String)
    endpoint = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Federated Catalog (PEM + Base64)")

# =====================================
# スキーマ定義
# =====================================
class CatalogItem(BaseModel):
    data_id: str
    user_id: str
    description: str
    endpoint: str
    signature: str  # Base64署名
    expire_time: str # UNIX時刻(署名の有効期限) 

class DeleteRequest(BaseModel):
    user_id: str
    signature: str
    expire_time: str # UNIX時刻(署名の有効期限) 

# =====================================
# 共通関数
# =====================================
def get_public_key(user_id: str):
    """Public-Key-RegistryからPEM公開鍵を取得"""
    try:
        res = requests.get(f"{PUBLIC_KEY_REGISTRY_URL}/get/{user_id}")
        if res.status_code != 200:
            raise HTTPException(status_code=403, detail="Public key not found.")
        data = res.json()
        fetched_pubkey_pem = data.get("public_key")
        return fetched_pubkey_pem
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch public key: {e}")

    
def verify_signature(public_key_pem: str, message: str, signature_b64: str):
    """PEM公開鍵 + Base64署名で検証"""
    try:
        vk = VerifyingKey.from_pem(public_key_pem)
        signature = base64.b64decode(signature_b64)
        vk.verify(signature, message.encode("utf-8"))
        return True
    except BadSignatureError:
        raise HTTPException(status_code=403, detail="Invalid signature.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signature verification error: {e}")

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

# =====================================
# API
# =====================================
@app.post("/add")
def add_entry(item: CatalogItem):
    db = SessionLocal()
    try:
        fetched_pubkey_pem = get_public_key(item.user_id)
        message = item.data_id + item.user_id + item.description + item.endpoint + item.expire_time
        
        check_expire_time(item.expire_time)
        verify_signature(fetched_pubkey_pem, message, item.signature)

        if db.query(FederatedCatalog).filter_by(data_id=item.data_id).first():
            raise HTTPException(status_code=400, detail="DataID already exists.")

        entry = FederatedCatalog(
            data_id=item.data_id,
            user_id=item.user_id,
            description=item.description,
            endpoint=item.endpoint,
            created_at=datetime.utcnow()
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return {"message": "Added successfully.", "data": item.dict()}
    finally:
        db.close()

@app.delete("/delete/{data_id}")
def delete_entry(data_id: str, req: DeleteRequest):
    db = SessionLocal()
    try:
        public_key = get_public_key(req.user_id)
        message = data_id + req.user_id + req.expire_time

        check_expire_time(req.expire_time)
        verify_signature(public_key, message, req.signature)

        entry = db.query(FederatedCatalog).filter_by(data_id=data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="DataID not found.")
        if entry.user_id != req.user_id:
            raise HTTPException(status_code=403, detail="User not authorized.")

        db.delete(entry)
        db.commit()
        return {"message": f"{data_id} deleted successfully."}
    finally:
        db.close()

@app.get("/get/{data_id}")
def get_by_dataid(data_id: str):
    db = SessionLocal()
    try:
        entry = db.query(FederatedCatalog).filter(FederatedCatalog.data_id == data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="DataID not found.")
        return entry.__dict__
    finally:
        db.close()

@app.post("/reset")
def reset_all():
    db = SessionLocal()
    try:
        num_deleted = db.query(FederatedCatalog).delete()
        db.commit()
        return {"message": f"All {num_deleted} entries deleted."}
    finally:
        db.close()

# 検索機能関係
@app.get("/search_by_keyword/{keyword}")
def search_by_keyword(keyword: str):
    """description に keyword が含まれるカタログを部分一致で検索。"""
    db = SessionLocal()
    try:
        results = db.query(FederatedCatalog).filter(
            FederatedCatalog.description.ilike(f"%{keyword}%")
        ).all()
        return {
            "query_type": "search_by_keyword",
            "query_value": keyword,
            "count": len(results),
            "results": [
                {
                    "data_id": r.data_id,
                    "user_id": r.user_id,
                    "description": r.description,
                    "endpoint": r.endpoint,
                    "created_at": r.created_at
                }
                for r in results
            ]
        }
    finally:
        db.close()


@app.get("/search_by_user_id/{user_id}")
def search_by_user_id(user_id: str):
    """指定された user_id に紐づくカタログ一覧を取得。"""
    db = SessionLocal()
    try:
        results = db.query(FederatedCatalog).filter(
            FederatedCatalog.user_id == user_id
        ).all()
        return {
            "query_type": "search_by_user_id",
            "query_value": user_id,
            "count": len(results),
            "results": [
                {
                    "data_id": r.data_id,
                    "user_id": r.user_id,
                    "description": r.description,
                    "endpoint": r.endpoint,
                    "created_at": r.created_at
                }
                for r in results
            ]
        }
    finally:
        db.close()

