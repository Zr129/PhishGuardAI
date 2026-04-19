"""
Lists controller — CRUD endpoints for user blacklist and whitelist.

GET  /lists           → returns both lists
POST /lists/blacklist → add domain to user blacklist
POST /lists/whitelist → add domain to user whitelist
DELETE /lists/blacklist/{domain} → remove from blacklist
DELETE /lists/whitelist/{domain} → remove from whitelist
"""

import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger("PhishGuard")


class DomainRequest(BaseModel):
    domain: str


def build_lists_router(user_list_provider, limiter: Limiter) -> APIRouter:
    router = APIRouter(prefix="/lists")

    @router.get("")
    @limiter.limit("60/minute")
    def get_lists(request: Request):
        """Return both user lists."""
        return {
            "blacklist": user_list_provider.get_blacklist(),
            "whitelist": user_list_provider.get_whitelist(),
        }

    @router.post("/blacklist")
    @limiter.limit("60/minute")
    def add_blacklist(request: Request, body: DomainRequest):
        added = user_list_provider.add_blacklist(body.domain)
        if not added:
            raise HTTPException(400, detail="Domain already in blacklist or invalid")
        return {"status": "added", "domain": body.domain, "list": "blacklist"}

    @router.post("/whitelist")
    @limiter.limit("60/minute")
    def add_whitelist(request: Request, body: DomainRequest):
        added = user_list_provider.add_whitelist(body.domain)
        if not added:
            raise HTTPException(400, detail="Domain already in whitelist or invalid")
        return {"status": "added", "domain": body.domain, "list": "whitelist"}

    @router.delete("/blacklist/{domain}")
    @limiter.limit("60/minute")
    def remove_blacklist(request: Request, domain: str):
        removed = user_list_provider.remove_blacklist(domain)
        if not removed:
            raise HTTPException(404, detail="Domain not found in blacklist")
        return {"status": "removed", "domain": domain, "list": "blacklist"}

    @router.delete("/whitelist/{domain}")
    @limiter.limit("60/minute")
    def remove_whitelist(request: Request, domain: str):
        removed = user_list_provider.remove_whitelist(domain)
        if not removed:
            raise HTTPException(404, detail="Domain not found in whitelist")
        return {"status": "removed", "domain": domain, "list": "whitelist"}

    return router
