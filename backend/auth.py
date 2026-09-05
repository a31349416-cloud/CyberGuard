"""
JWT Auth — легкий, без БД (користувачі в пам'яті/файл, або single-user режим)
Якщо JWT_SECRET не заданий — працює anonymous режим (як раніше)
"""
import os
import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, Header
from pathlib import Path
import json

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = "HS256"
JWT_EXPIRE_HOURS = 24

# Проста файлова БД користувачів (анонімний фолбек)
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
    return hashlib.sha256(pwd.encode()).hexdigest()

def create_user(username: str, password: str):
    users = _load_users()
    if username in users:
        raise ValueError("User exists")
    users[username] = {"pwd": hash_pwd(password), "created": datetime.now(timezone.utc).isoformat()}
    _save_users(users)
    return username

def verify_user(username: str, password: str) -> bool:
    users = _load_users()
    return users.get(username, {}).get("pwd") == hash_pwd(password)

def create_token(username: str) -> str:
    if not JWT_SECRET:
        return f"anon:{username}"
    payload = {"sub": username, "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS), "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> str:
    if not JWT_SECRET:
        # anon mode: token is anon:username
        if token.startswith("anon:"):
            return token.split(":", 1)[1]
        return "anonymous"
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return data.get("sub", "anonymous")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    if not JWT_SECRET:
        # Анонімний режим — якщо токен anon:username, поважаємо його (для тестів)
        if authorization and "anon:" in authorization:
            try:
                token = authorization.split(" ", 1)[1] if " " in authorization else authorization
                return decode_token(token)
            except:
                return "anonymous"
        return "anonymous"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1]
    return decode_token(token)

def get_optional_user(authorization: Optional[str] = Header(None)) -> str:
    if not JWT_SECRET:
        return "anonymous"
    if not authorization:
        return "anonymous"
    try:
        token = authorization.split(" ", 1)[1] if " " in authorization else authorization
        return decode_token(token)
    except:
        return "anonymous"
