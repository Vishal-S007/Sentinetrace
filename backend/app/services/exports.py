"""CSV / JSON exports.

Rows are read in batches and written to a spooled temporary file (in memory up to a few
MB, then on disk), which is then streamed to the client. Memory stays bounded and no
database session is held open while the response is sent. Every export has a row cap.
"""

import csv
import io
import json
import re
import tempfile
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import datetime
from typing import IO, Any, Literal

from fastapi.responses import StreamingResponse

ExportFormat = Literal["csv", "json"]
SPOOL_BYTES = 8 * 1024 * 1024
_NUMERIC = re.compile(r"^-?\d+(\.\d+)?$")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection (a cell starting with = + - @ ...).

    Such cells get a leading apostrophe so spreadsheet apps show them as text. Plain
    numbers (including negatives) and a lone "-" are left as they are.
    """
    if not isinstance(value, str) or not value:
        return value
    if value.startswith(_FORMULA_START) and value != "-" and not _NUMERIC.match(value):
        return "'" + value
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is not None and not isinstance(value, (str, int, float, bool, dict, list)):
        return str(value)  # e.g. IP address objects
    return value


class ExportResult:
    def __init__(self, file: IO[bytes], rows: int, truncated: bool):
        self.file, self.rows, self.truncated = file, rows, truncated


def write_export(
    fmt: ExportFormat,
    columns: Sequence[str],
    rows: Iterable[Sequence[Any]],
    cap: int,
) -> ExportResult:
    """Write at most `cap` rows; `rows` may yield one more to signal truncation."""
    spool: IO[bytes] = tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES)  # noqa: SIM115
    text = io.TextIOWrapper(spool, encoding="utf-8", newline="", write_through=True)
    count, truncated = 0, False
    if fmt == "csv":
        writer = csv.writer(text)
        writer.writerow(columns)
    else:
        text.write("[")
    for row in rows:
        if count == cap:
            truncated = True
            break
        values = [_plain(v) for v in row]
        if fmt == "csv":
            writer.writerow(
                [csv_safe(json.dumps(v) if isinstance(v, (dict, list)) else v) for v in values]
            )
        else:
            text.write(("," if count else "") + "\n")
            text.write(json.dumps(dict(zip(columns, values, strict=True)), ensure_ascii=False))
        count += 1
    if fmt == "json":
        text.write("\n]\n")
    text.detach()
    spool.seek(0)
    return ExportResult(spool, count, truncated)


def _chunks(file: IO[bytes]) -> Iterator[bytes]:
    try:
        while chunk := file.read(64 * 1024):
            yield chunk
    finally:
        file.close()


def export_response(result: ExportResult, fmt: ExportFormat, basename: str) -> StreamingResponse:
    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/json"
    return StreamingResponse(
        _chunks(result.file),
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{basename}.{fmt}"',
            "X-Export-Rows": str(result.rows),
            "X-Export-Truncated": "true" if result.truncated else "false",
        },
    )


def query_filters(params: Iterable[tuple[str, str]], skip: Callable[[str], bool]) -> dict[str, str]:
    """The filters an export used, for the audit trail."""
    return {k: v for k, v in params if not skip(k)}
