"""Safe storage of uploaded files.

* The client's filename is never used to build a path. Files are stored under their
  SHA-256: <storage>/files/ab/cd/<sha256>. The sanitized original name is display-only.
* Uploads stream to a temporary file while being hashed and size-checked, so an
  oversized upload is rejected without being held in memory.
* Binary and compressed content is rejected by inspecting the bytes, not the
  client-supplied Content-Type.
"""

import codecs
import hashlib
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

CHUNK = 1024 * 1024
SNIFF_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DENIED_EXTENSIONS = {
    ".gz",
    ".tgz",
    ".zip",
    ".bz2",
    ".xz",
    ".zst",
    ".7z",
    ".rar",
    ".tar",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
}
# Magic numbers of common compressed/binary formats.
_MAGIC = (
    b"\x1f\x8b",
    b"PK\x03\x04",
    b"BZh",
    b"\xfd7zXZ",
    b"7z\xbc\xaf",
    b"\x28\xb5\x2f\xfd",
    b"%PDF",
    b"\x89PNG",
    b"\x7fELF",
    b"MZ",
)

ENCODING_UTF8 = "utf-8"
ENCODING_REPLACED = "utf-8 (invalid bytes replaced)"


class UploadRejected(Exception):
    """Raised with an HTTP status and a user-facing message."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass
class StagedUpload:
    temp_path: Path
    sha256: str
    size: int
    encoding: str


def sanitize_filename(name: str | None) -> str:
    """A display-safe version of the client's filename (never used as a path)."""
    raw = (name or "").replace("\\", "/").split("/")[-1]
    raw = unicodedata.normalize("NFC", raw)
    cleaned = "".join(ch for ch in raw if ch.isprintable() and ch not in '<>:"|?*').strip(" .")
    return cleaned[:255] or "upload.log"


def _check_extension(display_name: str) -> None:
    lower = display_name.lower()
    for ext in _DENIED_EXTENSIONS:
        if lower.endswith(ext):
            raise UploadRejected(
                415, f"'{ext}' files are not supported. Upload the uncompressed text log."
            )


def _sniff(head: bytes) -> None:
    if head.startswith(_MAGIC):
        raise UploadRejected(415, "This looks like a compressed or binary file, not a text log.")
    if b"\x00" in head:
        raise UploadRejected(415, "The file contains NUL bytes; only text logs are accepted.")
    if head:
        control = sum(1 for b in head if b < 32 and b not in (9, 10, 13))
        if control / len(head) > 0.05:
            raise UploadRejected(415, "The file does not look like a text log.")


def stage_upload(
    stream: BinaryIO, display_name: str, storage_dir: Path, max_bytes: int
) -> StagedUpload:
    """Stream to a temp file under storage_dir, hashing and validating as we go."""
    _check_extension(display_name)
    tmp_dir = storage_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    valid_utf8 = True
    size = 0
    fd, name = tempfile.mkstemp(dir=tmp_dir, prefix="upload-")
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            first = True
            while chunk := stream.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadRejected(
                        413, f"File exceeds the upload limit of {max_bytes // (1024 * 1024)} MB."
                    )
                if first:
                    _sniff(chunk[:SNIFF_BYTES])
                    first = False
                if valid_utf8:
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError:
                        valid_utf8 = False
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise UploadRejected(422, "The file is empty.")
        if valid_utf8:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                valid_utf8 = False
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return StagedUpload(
        path, digest.hexdigest(), size, ENCODING_UTF8 if valid_utf8 else ENCODING_REPLACED
    )


def storage_key_for(sha256: str) -> str:
    if not _HEX64.match(sha256):
        raise ValueError("invalid sha256")
    return f"files/{sha256[:2]}/{sha256[2:4]}/{sha256}"


def resolve_storage_path(storage_dir: Path, storage_key: str) -> Path:
    """Map a storage key to a path, refusing anything that escapes the storage root."""
    root = storage_dir.resolve()
    path = (root / storage_key).resolve()
    if not path.is_relative_to(root):
        raise ValueError("storage key escapes the storage directory")
    return path


def commit_upload(staged: StagedUpload, storage_dir: Path) -> str:
    """Move a staged upload to its content-addressed location; returns the storage key."""
    key = storage_key_for(staged.sha256)
    final = resolve_storage_path(storage_dir, key)
    final.parent.mkdir(parents=True, exist_ok=True)
    if final.exists():
        staged.temp_path.unlink(missing_ok=True)  # identical content already stored
    else:
        os.replace(staged.temp_path, final)
        os.chmod(final, 0o440)
    return key


def discard(staged: StagedUpload) -> None:
    staged.temp_path.unlink(missing_ok=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
