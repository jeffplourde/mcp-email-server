import hmac
import logging
import os

import typer

from mcp_email_server.app import capability_summary, mcp
from mcp_email_server.config import delete_settings

app = typer.Typer()

logger = logging.getLogger(__name__)

# Paths served without a bearer token. Keep this minimal: a liveness probe must
# not require the secret, but nothing that touches mail may appear here.
PUBLIC_PATHS = ("/healthz",)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <token>` on every request except PUBLIC_PATHS.

    Pure ASGI so it wraps the MCP app without depending on Starlette internals.
    The comparison is constant-time; the presented token is never logged.
    """

    def __init__(self, app, token: str, public_paths: tuple[str, ...] = PUBLIC_PATHS):
        self._app = app
        self._token = token
        self._public_paths = public_paths

    @staticmethod
    async def _respond(send, status: int, body: bytes, headers: list[tuple[bytes, bytes]] | None = None):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"), *(headers or [])],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._public_paths:
            await self._respond(send, 200, b"ok")
            return

        headers = dict(scope.get("headers") or [])
        raw = headers.get(b"authorization", b"").decode("latin-1")
        presented = raw[7:].strip() if raw[:7].lower() == "bearer " else ""

        if not presented or not hmac.compare_digest(presented, self._token):
            client = scope.get("client") or ("?", 0)
            logger.warning(
                "rejected unauthenticated request path=%s client=%s reason=%s",
                path,
                client[0],
                "missing" if not presented else "mismatch",
            )
            await self._respond(send, 401, b"unauthorized", [(b"www-authenticate", b"Bearer")])
            return

        await self._app(scope, receive, send)


@app.command()
def stdio():
    mcp.run(transport="stdio")


@app.command()
def sse(
    host: str = "localhost",
    port: int = 9557,
):
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.run(transport="sse")


@app.command()
def streamable_http(
    host: str = os.environ.get("MCP_HOST", "localhost"),
    port: int = int(os.environ.get("MCP_PORT", 9557)),
):
    mcp.settings.host = host
    mcp.settings.port = port

    token = os.environ.get("MCP_EMAIL_SERVER_BEARER_TOKEN", "").strip()
    allow_no_auth = _env_bool("MCP_EMAIL_SERVER_ALLOW_NO_AUTH", default=False)

    logger.info("capabilities: %s", capability_summary())

    if not token:
        # Fail closed: this transport listens on a socket, and the server has no
        # other authentication of its own. Refuse rather than silently serving a
        # mailbox to anyone who can reach the port.
        if not allow_no_auth:
            raise SystemExit(
                "refusing to start: MCP_EMAIL_SERVER_BEARER_TOKEN is not set.\n"
                "Set it to require `Authorization: Bearer <token>`, or set\n"
                "MCP_EMAIL_SERVER_ALLOW_NO_AUTH=true to serve with no authentication\n"
                "(only sane when something else in front is already authenticating)."
            )
        logger.warning("starting WITHOUT authentication (MCP_EMAIL_SERVER_ALLOW_NO_AUTH=true)")
        mcp.run(transport="streamable-http")
        return

    import uvicorn

    uvicorn.run(
        BearerAuthMiddleware(mcp.streamable_http_app(), token),
        host=host,
        port=port,
        log_level=mcp.settings.log_level.lower(),
    )


@app.command()
def ui():
    from mcp_email_server.ui import main as ui_main

    ui_main()


@app.command()
def reset():
    delete_settings()
    typer.echo("✅ Config reset")


if __name__ == "__main__":
    app(["stdio"])
