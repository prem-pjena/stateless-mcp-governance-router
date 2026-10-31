import time
import uuid

import jwt
from pydantic import BaseModel

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class TokenError(Exception):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TokenClaims(BaseModel):
    iss: str
    sub: str
    aud: str
    scope: str = ""
    exp: int
    iat: int
    jti: str
    tenant_id: str | None = None

    def scopes(self) -> set[str]:
        return {item for item in self.scope.split() if item}

    def has_scope(self, required: str) -> bool:
        scopes = self.scopes()
        return required in scopes or "mcp:admin" in scopes


def mint_access_token(
    *,
    issuer: str,
    subject: str,
    audience: str,
    scope: str,
    ttl_seconds: int,
    signing_key,
    kid: str,
    tenant_id: str | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "scope": scope,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    if tenant_id:
        payload["tenant_id"] = tenant_id
    return jwt.encode(payload, signing_key, algorithm="EdDSA", headers={"kid": kid})


def verify_access_token(
    token: str,
    public_key,
    *,
    issuer: str,
    audience: str,
    skew_seconds: int,
) -> TokenClaims:
    options = {"require": ["exp", "iat", "iss", "aud", "sub", "jti"]}
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=audience,
            leeway=skew_seconds,
            options=options,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token_expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise TokenError("token_not_yet_valid") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("invalid_audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError("invalid_issuer") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenError("invalid_signature") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("invalid_token", str(exc)) from exc

    return TokenClaims(**payload)


def verify_client_assertion(
    assertion: str,
    public_key,
    *,
    client_id: str,
    audience: str,
    max_ttl_seconds: int,
    skew_seconds: int,
) -> dict:
    try:
        claims = jwt.decode(
            assertion,
            public_key,
            algorithms=["EdDSA"],
            audience=audience,
            options={"require": ["iss", "sub", "aud", "exp", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("assertion_expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("invalid_client_assertion", "aud mismatch") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenError("invalid_client_assertion", "signature") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("invalid_client_assertion", str(exc)) from exc

    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise TokenError("invalid_client_assertion", "iss/sub must equal client_id")

    now = int(time.time())
    if claims["exp"] - now > max_ttl_seconds + skew_seconds:
        raise TokenError("invalid_client_assertion", "assertion lifetime too long")

    return claims
