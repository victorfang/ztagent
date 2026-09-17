# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""OIDC JWT verification compatible with Keycloak, Auth0, and similar providers."""

from __future__ import annotations

import asyncio
from typing import Any

import anyio
import jwt
from fastapi import HTTPException, Request, status
from jwt import PyJWKClient

from .config import AuthConfig
from .models import Principal


class JWTAuthenticator:
    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._jwks = PyJWKClient(config.jwks_url, timeout=5, lifespan=300)
        self._verification_slots = asyncio.Semaphore(20)

    def verify(self, token: str) -> Principal:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.config.algorithms,
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        roles = _nested_claim(claims, self.config.role_claim)
        if isinstance(roles, str):
            normalized_roles = frozenset(roles.split())
        elif isinstance(roles, list):
            normalized_roles = frozenset(str(role) for role in roles)
        else:
            normalized_roles = frozenset()
        return Principal(subject=str(claims["sub"]), roles=normalized_roles, claims=claims)

    async def __call__(self, request: Request) -> Principal:
        if not self.config.enabled:
            return Principal(subject="development-user", roles=frozenset({"msa-admin"}))
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if len(token) > self.config.max_token_chars:
            raise HTTPException(status_code=401, detail="Access token is too large")
        async with self._verification_slots:
            return await anyio.to_thread.run_sync(self.verify, token)


def _nested_claim(claims: dict[str, Any], path: str) -> Any:
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value
