from contextvars import ContextVar

from .tokens import TokenClaims

_current: ContextVar[TokenClaims | None] = ContextVar("current_claims", default=None)


def set_claims(claims: TokenClaims):
    return _current.set(claims)


def reset_claims(token) -> None:
    _current.reset(token)


def current_claims() -> TokenClaims | None:
    return _current.get()
