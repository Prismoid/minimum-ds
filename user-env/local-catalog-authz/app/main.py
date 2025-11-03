from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, String, DateTime, ForeignKey, func, PrimaryKeyConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
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
DB_NAME = os.getenv("POSTGRES_DB", "local_catalog_authz_db")
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
class LocalCatalog(Base):
    __tablename__ = "local_catalog"
    data_id = Column(String, primary_key=True, index=True)
    description = Column(String)
    admin_id = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # 一対多（Data 1件に複数のAuthorization）
    authorizations = relationship("LocalAuthorization", cascade="all, delete-orphan")


class LocalAuthorization(Base):
    __tablename__ = "local_authorization"
    data_id = Column(String, ForeignKey("local_catalog.data_id", ondelete="CASCADE"))
    access_grantee_id = Column(String)
    expire_at = Column(DateTime(timezone=True), nullable=False)  # 有効期限を追加
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        PrimaryKeyConstraint("data_id", "access_grantee_id", name="pk_authz"),
    )

Base.metadata.create_all(bind=engine)

# =====================================
# FastAPI アプリ設定
# =====================================
app = FastAPI(
    title="Local Catalog AuthZ Service",
    description="Local service managing dataset metadata and access authorizations (AuthZ) in PostgreSQL.",
    version="1.0.0",
)

# =====================================
# スキーマ定義
# =====================================
class DataItem(BaseModel):
    data_id: str
    description: str | None = None
    admin_id: str
    endpoint: str
    expire_time: str
    signature: str

class AuthZItem(BaseModel):
    data_id: str
    access_grantee_id: str
    expire_at: str  # ISO8601形式で送信 (例: "2025-11-03T12:00:00Z")
    expire_time: str
    signature: str
    
# データ取得用(これは、カタログ情報、認可情報両方で使用する)
class SignedGetRequest(BaseModel):
    """署名付きデータ取得・認可取得用リクエストスキーマ。管理者IDの署名が必須。"""
    admin_id: str            # データ管理者のユーザID
    expire_time: str        # ISO8601形式の署名有効期限 (例: "2025-11-03T12:00:00Z")
    signature: str          # Base64エンコードされたデジタル署名

# データ削除用(カタログデータ)
class SignedDeleteCatalogRequest(BaseModel):
    """署名付き削除リクエストスキーマ。管理者IDの署名が必須。"""
    description: str | None = None # データの記述
    admin_id: str                  # データ管理者のユーザID
    endpoint: str                  # URL
    expire_time: str               # ISO8601形式の署名有効期限 (例: "2025-11-03T12:00:00Z")
    signature: str                 # Base64エンコードされたデジタル署名

# データ削除用(認可データ)
class SignedDeleteAuthZRequest(BaseModel):
    """署名付き削除リクエストスキーマ。管理者IDの署名が必須。"""
    expire_time: str               # ISO8601形式の署名有効期限 (例: "2025-11-03T12:00:00Z")
    signature: str                 # Base64エンコードされたデジタル署名


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

def get_admin_id_by_data_id(db, data_id: str) -> str:
    """指定された data_id に対応する管理者ID (admin_id) を取得する共通関数。対応するデータが存在しない場合は 404 を返す。"""
    try:
        entry = db.query(LocalCatalog.admin_id).filter_by(data_id=data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail=f"DataID '{data_id}' not found in catalog.")
        return entry.admin_id
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve admin_id for DataID '{data_id}': {e}")


    
# =====================================
# DBセッション
# =====================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

        

# =====================================
# API エンドポイント
# =====================================

@app.get("/")
def root():
    return {"message": "Local Catalog AuthZ Server running"}


# ---- データ登録 ----
@app.post("/add_data")
def add_data(item: DataItem):
    db = next(get_db())
    try:
        # 有効期限切れと公開鍵を取得して署名検証
        check_expire_time(item.expire_time)
        fetched_pubkey_pem = get_public_key(item.admin_id)
        msg = item.data_id + item.description + item.admin_id + item.endpoint + item.expire_time
        verify_signature(fetched_pubkey_pem, msg, item.signature)
        
        if db.query(LocalCatalog).filter_by(data_id=item.data_id).first():
            raise HTTPException(status_code=400, detail="DataID already exists.")
        new_entry = LocalCatalog(
            data_id=item.data_id,
            description=item.description,
            admin_id=item.admin_id,
            endpoint=item.endpoint,
        )
        db.add(new_entry)
        db.commit()
        return {"message": f"Data {item.data_id} registered successfully."}
    finally:
        db.close()

# ---- 認可登録 (AuthZ) ----
@app.post("/add_authz")
def add_authz(item: AuthZItem):
    db =next(get_db())
    try:
        # 有効期限切れと公開鍵を取得して署名検証
        check_expire_time(item.expire_time)
        admin_id = get_admin_id_by_data_id(db, item.data_id)
        fetched_pubkey_pem = get_public_key(admin_id)
        msg = item.data_id + item.access_grantee_id + item.expire_at + item.expire_time
        verify_signature(fetched_pubkey_pem, msg, item.signature)
        
        if not db.query(LocalCatalog).filter_by(data_id=item.data_id).first():
            raise HTTPException(status_code=404, detail="DataID not found.")
        existing = db.query(LocalAuthorization).filter_by(
            data_id=item.data_id, access_grantee_id=item.access_grantee_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="AuthZ already exists.")

        # 有効期限をISO8601文字列からdatetimeに変換
        try:
            expire_dt = datetime.fromisoformat(item.expire_at.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid expire_at format")

        new_authz = LocalAuthorization(
            data_id=item.data_id,
            access_grantee_id=item.access_grantee_id,
            expire_at=expire_dt,
        )
        db.add(new_authz)
        db.commit()
        return {"message": f"AuthZ added for {item.access_grantee_id} (expires {item.expire_at})."}
    finally:
        db.close()


# ---- データ情報取得(署名必要) ----
@app.post("/get_data/{data_id}")
def get_data(data_id: str, req: SignedGetRequest):
    db = next(get_db())
    try:
        entry = db.query(LocalCatalog).filter_by(data_id=data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="DataID not found.")
        if req.admin_id != entry.admin_id:
            raise HTTPException(status_code=403, detail="User not authorized.")

        # 公開鍵を取得して署名検証
        check_expire_time(req.expire_time)
        fetched_pubkey_pem = get_public_key(req.admin_id)
        verify_signature(fetched_pubkey_pem, req.expire_time, req.signature)

        # 認証成功 → データ返却
        return {
            "data_id": entry.data_id,
            "description": entry.description,
            "admin_id": entry.admin_id,
            "endpoint": entry.endpoint,
            "created_at": entry.created_at,
        }
    finally:
        db.close()

"""認可情報取得(管理者のデジタル署名が必須)Public-Key-Registryで公開鍵を取得して署名検証。"""
@app.post("/get_authz/{data_id}")
def get_authz(data_id: str, req: SignedGetRequest):
    db = next(get_db())
    try:
        # 1. 対象データ取得
        entry = db.query(LocalCatalog).filter_by(data_id=data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="DataID not found.")
        # 2. 管理者確認
        if req.admin_id != entry.admin_id:
            raise HTTPException(status_code=403, detail="User not authorized.")
        # 3. 有効期限チェック
        check_expire_time(req.expire_time)
        # 4. 公開鍵取得 & 署名検証
        fetched_pubkey_pem = get_public_key(req.admin_id)
        verify_signature(fetched_pubkey_pem, req.expire_time, req.signature)
        # 5. 有効な認可情報のみ返却
        now = datetime.now(timezone.utc)
        results = db.query(LocalAuthorization).filter(
            LocalAuthorization.data_id == data_id,
            LocalAuthorization.expire_at > now
        ).all()
        return {
            "data_id": data_id,
            "valid_authz_count": len(results),
            "valid_authz": [
                {
                    "access_grantee_id": r.access_grantee_id,
                    "expire_at": r.expire_at,
                } for r in results
            ]
        }
    finally:
        db.close()



        
# ---- データ削除（関連認可も削除） ----
@app.post("/delete_data/{data_id}")
def delete_data(data_id: str, req: SignedDeleteCatalogRequest): 
    db = next(get_db())
    try:
        # データ存在確認
        entry = db.query(LocalCatalog).filter_by(data_id=data_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="DataID not found.")
        # 各カラムの整合性を検証（リクエスト内容とDBの値が一致するか）
        if (
            data_id != entry.data_id or
            req.admin_id != entry.admin_id or
            req.endpoint != entry.endpoint or
            (req.description or "") != (entry.description or "")
        ):
            raise HTTPException(status_code=400, detail="Request data does not match stored record.")
        # 有効期限切れと公開鍵を取得して署名検証
        check_expire_time(req.expire_time)
        fetched_pubkey_pem = get_public_key(req.admin_id)
        msg = data_id + req.description + req.admin_id + req.endpoint + req.expire_time
        verify_signature(fetched_pubkey_pem, msg, req.signature)
        
        db.delete(entry)
        db.commit()
        return {"message": f"Data {data_id} and related AuthZ entries deleted."}
    finally:
        db.close()


# ---- 認可削除（該当のみ） ----
@app.post("/delete_authz/{data_id}/{access_grantee_id}")
def delete_authz(data_id: str, access_grantee_id: str, req: SignedDeleteAuthZRequest):
    db = next(get_db())
    try:
        auth = db.query(LocalAuthorization).filter_by(
            data_id=data_id, access_grantee_id=access_grantee_id
        ).first()
        if not auth:
            raise HTTPException(status_code=404, detail="AuthZ not found.")
        # 有効期限切れと公開鍵を取得して署名検証
        check_expire_time(req.expire_time)
        admin_id = get_admin_id_by_data_id(db, data_id)
        fetched_pubkey_pem = get_public_key(admin_id)
        msg = data_id + access_grantee_id + req.expire_time
        verify_signature(fetched_pubkey_pem, msg, req.signature)
        
        db.delete(auth)
        db.commit()
        return {"message": f"AuthZ for {access_grantee_id} on {data_id} deleted."}
    finally:
        db.close()


# ---- 一覧取得 ----
@app.get("/debug_all")
def debug_all():
    db = next(get_db())
    try:
        data = db.query(LocalCatalog).all()
        authz = db.query(LocalAuthorization).all()
        return {
            "catalog_count": len(data),
            "authz_count": len(authz),
            "catalog": [
                {
                    "data_id": d.data_id,
                    "admin_id": d.admin_id,
                    "endpoint": d.endpoint,
                    "created_at": d.created_at,
                } for d in data
            ],
            "authz": [
                {
                    "data_id": a.data_id,
                    "access_grantee_id": a.access_grantee_id,
                    "expire_at": a.expire_at,
                } for a in authz
            ]
        }
    finally:
        db.close()


@app.post("/reset")
def reset_all():
    db = next(get_db())
    try:
        num_authz = db.query(LocalAuthorization).delete()
        num_data = db.query(LocalCatalog).delete()
        db.commit()
        return {"message": f"Reset done: {num_data} catalog, {num_authz} authz removed."}
    finally:
        db.close()
