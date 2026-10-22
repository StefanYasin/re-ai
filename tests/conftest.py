"""Shared fixtures: a synthetic PE, an optional compiled PE, and a fake API."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pe_builder  # noqa: E402

C_SOURCE = """#include <stdio.h>
int main(void) {
    puts("re-ai compiled fixture");
    return 0;
}
"""


def _find_mingw() -> str | None:
    for candidate in ("x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc", "gcc"):
        executable = shutil.which(candidate)
        if not executable:
            continue
        try:
            result = subprocess.run(
                [executable, "-dumpmachine"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if "mingw" in result.stdout.lower():
            return executable
    return None


@pytest.fixture(scope="session")
def synthetic_pe_bytes() -> bytes:
    return pe_builder.build_minimal_pe()


@pytest.fixture(scope="session")
def synthetic_pe_x64() -> bytes:
    return pe_builder.build_minimal_pe(is_64=True)


@pytest.fixture(scope="session")
def compiled_pe_bytes(tmp_path_factory) -> bytes:
    """A real compiler output when a mingw gcc is on PATH, else skip."""
    compiler = _find_mingw()
    if compiler is None:
        pytest.skip("no mingw capable gcc found")
    workdir = tmp_path_factory.mktemp("compiled-pe")
    source = workdir / "fixture.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    target = workdir / "fixture.exe"
    result = subprocess.run(
        [compiler, "-O1", "-o", str(target), str(source)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        pytest.skip(f"fixture compile failed: {result.stderr[:300]}")
    data = target.read_bytes()
    if not data.startswith(b"MZ"):
        pytest.skip("compiler did not emit a PE file")
    return data


class FakeLLMServer:
    """Local OpenAI compatible endpoint. No network access, no real key."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status = 200
        self.content = "## What it appears to do\nIt looks like a console program."
        self.raw_body: str | None = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = {"unparsed": body.decode("utf-8", "replace")}
                owner.requests.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "body": parsed,
                    }
                )
                if owner.raw_body is not None:
                    payload = owner.raw_body.encode("utf-8")
                else:
                    payload = json.dumps(
                        {
                            "model": "fake-model",
                            "choices": [{"message": {"role": "assistant", "content": owner.content}}],
                        }
                    ).encode("utf-8")
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def __enter__(self) -> "FakeLLMServer":
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def fake_llm_server():
    with FakeLLMServer() as server:
        yield server
