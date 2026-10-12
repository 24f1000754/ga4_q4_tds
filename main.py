
import os

import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-etugcojy.apps.exam.local"

# Paste the complete assigned PEM public key here.
PUBLIC_KEY = os.environ.get("IDP_PUBLIC_KEY", """PASTE_YOUR_COMPLETE_PUBLIC_KEY_HERE""")


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
            options={
                "require": ["exp", "iss", "aud", "sub"]
            },
        )

        return {
            "valid": True,
            "email": claims.get("email", ""),
            "sub": claims.get("sub", ""),
            "aud": claims.get("aud", ""),
        }

    except jwt.PyJWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
