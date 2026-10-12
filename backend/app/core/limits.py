"""Request body size limits, enforced before the body is parsed."""

import re

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_UPLOAD_PATH = re.compile(r"^/api/sources/\d+/files$")
MULTIPART_OVERHEAD = 1024 * 1024
DEFAULT_LIMIT = 1024 * 1024  # JSON endpoints


class BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject oversized request bodies with 413.

    Uploads get ST_MAX_UPLOAD_BYTES (+ multipart overhead); everything else 1 MB. Checks
    Content-Length up front and also counts streamed bytes, so chunked requests without
    a Content-Length can't bypass the limit.
    """

    def __init__(self, app: ASGIApp, max_upload_bytes: int) -> None:
        self.app = app
        self.upload_limit = max_upload_bytes + MULTIPART_OVERHEAD

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.upload_limit if _UPLOAD_PATH.match(scope["path"]) else DEFAULT_LIMIT
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await self._reject(send)
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not response_started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
