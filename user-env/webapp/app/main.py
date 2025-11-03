from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import requests, base64, hashlib

app = FastAPI(title="WebApp for Connector Dashboard")
templates = Jinja2Templates(directory="app/templates")

CONNECTOR_URL = "http://host.docker.internal:51000"  # Connector API URL

# ===== 共通関数 =====
def hash_password(password: str) -> str:
    """SHA256 ハッシュ化（PoC用、saltなし）"""
    return hashlib.sha256(password.encode()).hexdigest()

def basic_auth_header(user_id: str, password_hash: str):
    """
    Basic Auth で password_hash を利用
    """
    token = base64.b64encode(f"{user_id}:{password_hash}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# ===== トップページ（ログイン後はダッシュボードとして表示） =====
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """
    - user_id / password_hash がクエリに含まれている場合 → ダッシュボード
    - それ以外の場合 → ログイン前のトップ画面
    """
    user_id = request.query_params.get("user_id")
    password_hash = request.query_params.get("password_hash")

    user_info = None
    registry_info = None
    search_result = None
    error = None

    if user_id and password_hash:
        try:
            headers = basic_auth_header(user_id, password_hash)

            # 1. Connector の /users/{user_id}
            res_user = requests.get(f"{CONNECTOR_URL}/users/{user_id}", headers=headers)
            if res_user.status_code == 200:
                user_info = res_user.json()
            else:
                error = f"Failed to fetch user info: {res_user.status_code} {res_user.text}"

            # 2. Connector の /debug_all_pk_users
            res_pk = requests.get(f"{CONNECTOR_URL}/debug_all_pk_users", headers=headers)
            if res_pk.status_code == 200:
                registry_info = res_pk.json()
            else:
                if error:
                    error += " / "
                error = (error or "") + f"Failed to fetch registry info: {res_pk.status_code}"

            # 3. Connector の /search_by_keyword/
            res_pk = requests.get(f"{CONNECTOR_URL}/search_by_keyword/IoT", headers=headers)
            if res_pk.status_code == 200:
                search_result = res_pk.json()
            else:
                if error:
                    error += " / "
                error = (error or "") + f"Failed to fetch registry info: {res_pk.status_code}"

        except Exception as e:
            error = str(e)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user_id": user_id,
        "password_hash": password_hash,
        "user_info": user_info,
        "registry_info": registry_info,
        "search_result": search_result, 
        "error": error
    })


# ===== Register ページ =====
@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register", response_class=HTMLResponse)
def register_user(user_id: str = Form(...), password: str = Form(...)):
    password_hash = hash_password(password)
    res = requests.post(f"{CONNECTOR_URL}/register", json={
        "user_id": user_id,
        "password_hash": password_hash
    })
    if res.status_code == 200:
        return RedirectResponse(url=f"/?user_id={user_id}&password_hash={password_hash}", status_code=303)
    return HTMLResponse(f"<h3>Register failed: {res.status_code} {res.text}</h3>")


# ===== Login ページ =====
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
def login_user(user_id: str = Form(...), password: str = Form(...)):
    password_hash = hash_password(password)
    res = requests.post(f"{CONNECTOR_URL}/login", json={
        "user_id": user_id,
        "password_hash": password_hash
    })
    if res.status_code == 200:
        # 成功時: password_hash をクエリに渡して "/" にリダイレクト
        return RedirectResponse(
            url=f"/?user_id={user_id}&password_hash={password_hash}",
            status_code=303
        )
    return HTMLResponse(f"<h3>Login failed: {res.status_code} {res.text}</h3>")
