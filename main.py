
import os

import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-etugcojy.apps.exam.local"

PUBLIC_KEY = os.environ["IDP_PUBLIC_KEY"].replace("\\n", "\n")


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
def verify_token(body: TokenRequest):
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )

        return {
            "valid": True,
            "email": claims.get("email", ""),
            "sub": claims.get("sub", ""),
            "aud": claims.get("aud", ""),
        }

    except jwt.PyJWTError as e:
        print("JWT ERROR:", type(e).__name__, str(e))
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
