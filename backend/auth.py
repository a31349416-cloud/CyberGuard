"""
JWT Auth v2 — bcrypt + refresh token + RBAC
- Якщо JWT_SECRET не заданий — anonymous режим (backward compatible)
- Access token 15хв, Refresh 7 днів
- Ролі: user, admin (admin бачить всі скани)
"""
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, Header
from pathlib import Path
import json

import bcrypt

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = "HS256"
ACCESS_EXPIRE_MIN = 15
REFRESH_EXPIRE_DAYS = 7

USERS_PATH = Path(__file__).parent / "users.json"

def _load_users() -> dict:
    if USERS_PATH.exists():
        try:
            return json.loads(USERS_PATH.read_text(encoding="utf-8"))
        except:
            return {}
    return {}

def _save_users(users: dict):
    USERS_PATH.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")

def hash_pwd(pwd: str) -> str:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def verify_pwd(pwd: str, hashed: str) -> bool:
    # Підтримка старих sha256 для міграції
    if hashed.startswith("$2b$"):
        return bcrypt.checkpw(pwd.encode(), hashed.encode())
    # legacy sha256
    import hashlib
    return hashlib.sha256(pwd.encode()).hexdigest() == hashed

def create_user(username: str, password: str, role: str = "user"):
    users = _load_users()
    if username in users:
        raise ValueError("User exists")
    if role not in ("user", "admin"):
        role = "user"
    users[username] = {"pwd": hash_pwd(password), "role": role, "created": datetime.now(timezone.utc).isoformat()}
    _save_users(users)
    return username

def verify_user(username: str, password: str) -> bool:
    users = _load_users()
    u = users.get(username)
    if not u:
        return False
    return verify_pwd(password, u.get("pwd", ""))

def get_role(username: str) -> str:
    users = _load_users()
    return users.get(username, {}).get("role", "user")

def create_tokens(username: str) -> dict:
    now = datetime.now(timezone.utc)
    role = get_role(username)
    access_payload = {"sub": username, "role": role, "type": "access", "exp": now + timedelta(minutes=ACCESS_EXPIRE_MIN), "iat": now}
    refresh_payload = {"sub": username, "role": role, "type": "refresh", "exp": now + timedelta(days=REFRESH_EXPIRE_DAYS), "iat": now}
    if not JWT_SECRET:
        return {"access_token": f"anon:{username}", "refresh_token": f"anon_refresh:{username}", "token_type": "bearer"}
    access = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALG)
    refresh = jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

def create_token(username: str) -> str:
    return create_tokens(username)["access_token"]

def decode_token(token: str, expect_type: str = "access") -> dict:
    if not JWT_SECRET:
        if token.startswith("anon:"):
            return {"sub": token.split(":", 1)[1], "role": "user", "type": "access"}
        if token.startswith("anon_refresh:"):
            return {"sub": token.split(":", 1)[1], "role": "user", "type": "refresh"}
        return {"sub": "anonymous", "role": "user", "type": "access"}
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if expect_type and data.get("type") != expect_type:
            raise HTTPException(status_code=401, detail=f"Expected {expect_type} token")
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    if not JWT_SECRET:
        if authorization and "anon:" in authorization:
            try:
                token = authorization.split(" ", 1)[1] if " " in authorization else authorization
                return decode_token(token)["sub"]
            except:
                return "anonymous"
        return "anonymous"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1]
    return decode_token(token)["sub"]

def get_current_user_with_role(authorization: Optional[str] = Header(None)) -> dict:
    if not JWT_SECRET:
        if authorization and "anon:" in authorization:
            try:
                token = authorization.split(" ", 1)[1] if " " in authorization else authorization
                d = decode_token(token)
                return {"user": d["sub"], "role": d.get("role", "user")}
            except:
                pass
        return {"user": "anonymous", "role": "user"}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1]
    d = decode_token(token)
    return {"user": d["sub"], "role": d.get("role", "user")}

def get_optional_user(authorization: Optional[str] = Header(None)) -> str:
    if not JWT_SECRET:
        return "anonymous"
    if not authorization:
        return "anonymous"
    try:
        token = authorization.split(" ", 1)[1] if " " in authorization else authorization
        return decode_token(token)["sub"]
    except:
        return "anonymous"

def require_admin(user: dict = Depends(get_current_user_with_role)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user
