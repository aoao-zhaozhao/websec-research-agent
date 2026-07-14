"""Local JWT CTF lab for exercising the authenticated-session workflow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn


APP = FastAPI(title="JWT Session Lab", docs_url=None, redoc_url=None, openapi_url=None)
COOKIE_NAME = "token"
LAB_SECRET = os.getenv("JWT_LAB_SECRET", "development")
FLAG = os.getenv("JWT_LAB_FLAG", "shellmates{local_jwt_session_path_verified}")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_token(admin: bool) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url_encode(
        json.dumps(
            {"sub": {"admin": admin, "data": {"username": "zombo"}}, "iat": int(time.time()), "exp": int(time.time()) + 3600},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}"
    signature = _b64url_encode(hmac.new(LAB_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{signature}"


def read_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        header, payload, signature = token.split(".")
        signing_input = f"{header}.{payload}"
        expected = _b64url_encode(hmac.new(LAB_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(_b64url_decode(payload))
        return claims if int(claims.get("exp", 0)) >= time.time() else None
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


@APP.get("/", response_class=HTMLResponse)
@APP.get("/login", response_class=HTMLResponse)
def login_form() -> str:
    return """<!doctype html><title>Session Lab</title>
<h1>Login and just work type!</h1>
<p>Use the following account:</p>
<p>username: zombo<br>password: zombo</p>
<form method=post action=/login><input name=username><input name=password type=password><button>Login</button></form>"""


@APP.post("/login")
def login(username: str = Form(), password: str = Form()):
    if username != "zombo" or password != "zombo":
        return HTMLResponse("Invalid Username or Password", status_code=401)
    response = RedirectResponse("/home", status_code=302)
    response.set_cookie(COOKIE_NAME, make_token(False), httponly=True, samesite="lax")
    return response


@APP.get("/home", response_class=HTMLResponse)
def home(request: Request):
    claims = read_token(request.cookies.get(COOKIE_NAME))
    if not claims:
        return HTMLResponse("Login to access to home page")
    if claims.get("sub", {}).get("admin") is not True:
        return HTMLResponse("Sorry, you are not an admin")
    return HTMLResponse(f"<h1>Congratulations. Here is your flag</h1><p>{FLAG}</p>")


if __name__ == "__main__":
    uvicorn.run(APP, host="127.0.0.1", port=int(os.getenv("JWT_LAB_PORT", "19435")), log_level="warning")
