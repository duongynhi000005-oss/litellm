import aiohttp
from aiohttp import web
import pytest
from unittest.mock import MagicMock

from litellm.constants import AIOHTTP_MAX_FIELD_SIZE, AIOHTTP_MAX_LINE_SIZE
from litellm.proxy._experimental.mcp_server.faults.render_oauth import render_token_fault
from litellm.proxy._experimental.mcp_server.faults.types import UpstreamProtocolFault


def test_constants_defaults():
    """Verify Aiohttp parser constants default to 64KB (65536 bytes) instead of 8190."""
    assert AIOHTTP_MAX_LINE_SIZE == 65536
    assert AIOHTTP_MAX_FIELD_SIZE == 65536


@pytest.mark.asyncio
async def test_session_accepts_large_csp_headers():
    """Verify ClientSession with AIOHTTP_MAX_FIELD_SIZE accepts 9.5KB CSP headers (LIT-48468)."""
    app = web.Application()
    # 9.5 KB header simulating GitHub's Content-Security-Policy
    large_csp = "default-src 'none'; " + ("directive " * 900)
    assert len(large_csp) > 9000

    async def handler(request):
        return web.json_response(
            {"access_token": "gho_test_12345", "token_type": "bearer", "scope": "repo"},
            headers={"Content-Security-Policy": large_csp},
        )

    app.router.add_post("/login/oauth/access_token", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8989)
    await site.start()

    try:
        async with aiohttp.ClientSession(
            max_line_size=AIOHTTP_MAX_LINE_SIZE,
            max_field_size=AIOHTTP_MAX_FIELD_SIZE,
        ) as session:
            async with session.post("http://127.0.0.1:8989/login/oauth/access_token") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["access_token"] == "gho_test_12345"
    finally:
        await runner.cleanup()


def test_render_token_fault_format():
    """Verify UpstreamProtocolFault renders RFC 6749 compliant JSON with error string."""
    import json

    fault = UpstreamProtocolFault(note="failed to communicate with upstream token endpoint: LineTooLong")
    response = render_token_fault(fault)

    assert response.status_code == 502
    body = json.loads(response.body.decode("utf-8"))
    # RFC 6749 §5.2 requires "error" to be a string
    assert "error" in body
    assert body["error"] == "server_error"
    assert "error_description" in body
    assert "LineTooLong" in body["error_description"]
    # Must have cache-control headers
    assert response.headers["cache-control"] == "no-store"
