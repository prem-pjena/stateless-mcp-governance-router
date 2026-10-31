import base64
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def jwk_to_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")
    return Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"]))


class StaticKeySet:
    def __init__(self, keys: dict[str, Ed25519PublicKey]) -> None:
        self._keys = keys

    async def public_key(self, kid: str) -> Ed25519PublicKey | None:
        return self._keys.get(kid)


class RemoteJwks:
    """Caches the issuer key set; refetches only after the TTL or on an unknown kid."""

    def __init__(self, jwks_uri: str, ttl_seconds: int, timeout: float = 5.0) -> None:
        self._uri = jwks_uri
        self._ttl = ttl_seconds
        self._timeout = timeout
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at = 0.0

    async def public_key(self, kid: str) -> Ed25519PublicKey | None:
        if self._is_stale() or kid not in self._keys:
            await self.refresh()
        return self._keys.get(kid)

    def _is_stale(self) -> bool:
        return (time.monotonic() - self._fetched_at) > self._ttl

    async def refresh(self) -> None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(self._uri)
            response.raise_for_status()
            payload = response.json()

        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in payload.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = jwk_to_public_key(jwk)
            except ValueError:
                continue

        self._keys = keys
        self._fetched_at = time.monotonic()
