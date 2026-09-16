#!/usr/bin/env python3
"""Exercise actual hidden terminal entry/delivery with synthetic fixtures only."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time


BIN = str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/release/vault").resolve())
UNLOCK = "synthetic-terminal-unlock"
PASSWORD = "synthetic-terminal-value"


def exercise(root):
    home = root / "primary"

    def command(args, inputs, terminal=False, hidden=False, succeeds=True):
        base = [BIN, "--home", str(home)]
        if not terminal:
            result = subprocess.run(base + ["--secrets-stdin"] + args,
                                    input="".join(line + "\n" for line in inputs).encode(),
                                    capture_output=True, timeout=30)
            out, err, shown, code = result.stdout, result.stderr, b"", result.returncode
        else:
            # Child owns a controlling terminal; ordinary streams remain separate.
            out_path, err_path = root / "stdout", root / "stderr"
            read_fd, write_fd = os.pipe()
            pid, master = pty.fork()
            if pid == 0:
                os.close(write_fd)
                if not hidden:
                    # Keep the slave terminal open after redirecting all stdio;
                    # otherwise macOS detaches this newly created session's tty.
                    terminal_fd = os.dup(0)
                    os.set_inheritable(terminal_fd, True)
                    os.dup2(read_fd, 0)
                os.close(read_fd)
                for fd, path in [(1, out_path), (2, err_path)]:
                    with path.open("wb") as file:
                        os.dup2(file.fileno(), fd)
                os.execv(BIN, base + ([] if hidden else ["--secrets-stdin"]) + args)
            os.close(read_fd)
            if not hidden:
                os.write(write_fd, "".join(line + "\n" for line in inputs).encode())
            os.close(write_fd)
            shown, sent, prompt = b"", 0, b""
            deadline = time.monotonic() + 30
            status = None
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.05)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            chunk = b""
                        shown += chunk
                        prompt += chunk
                        if hidden and sent < len(inputs) and b": " in prompt:
                            # rpassword prints the prompt before disabling echo.
                            # Wait until the terminal really has ECHO cleared.
                            import termios
                            for _ in range(100):
                                if not termios.tcgetattr(master)[3] & termios.ECHO:
                                    break
                                time.sleep(0.01)
                            else:
                                raise AssertionError("terminal input echo was not disabled")
                            os.write(master, (inputs[sent] + "\n").encode())
                            sent += 1
                            prompt = b""
                    done, status = os.waitpid(pid, os.WNOHANG)
                    if done:
                        break
                else:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                    raise AssertionError("terminal command timed out")
            finally:
                os.close(master)
            code = os.waitstatus_to_exitcode(status)
            out, err = out_path.read_bytes(), err_path.read_bytes()
        safe_error = err.decode(errors="replace")
        for value in [UNLOCK, PASSWORD, "synthetic-recovery-code"]:
            safe_error = safe_error.replace(value, "[REDACTED]")
        assert (code == 0) == succeeds, f"unexpected exit {code}: {safe_error}"
        for value in [UNLOCK, PASSWORD, "synthetic-recovery-code"]:
            assert value.encode() not in out + err, "secret entered ordinary output"
            if hidden:
                assert value.encode() not in shown, "hidden entry echoed"
        return (json.loads(out) if out else None), shown

    command(["init", "--recovery-file", str(root / "factor")], [UNLOCK, UNLOCK], terminal=True, hidden=True)
    password, _ = command(["add", "password", "--label", "test", "--scope", "test", "--revealable"], [UNLOCK, PASSWORD], terminal=True, hidden=True)
    for name in ["a", "b"]:
        command(["replica-add", "--path", str(root / name), "--failure-domain", name], [UNLOCK])
    result, shown = command(["show", password["id"]], [UNLOCK], terminal=True)
    assert PASSWORD.encode() in shown
    assert result["result"]["delivered_to"] == "controlling-terminal"

    # RFC 4226 public vector (ASCII 12345678901234567890), encoded as base32.
    hotp, _ = command(["add", "hotp", "--label", "test otp", "--scope", "test"], [UNLOCK, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"])
    request = "81" * 32
    first, shown = command(["--request", request, "otp", hotp["id"]], [UNLOCK], terminal=True)
    assert b"755224" in shown
    retry, shown = command(["--request", request, "otp", hotp["id"]], [UNLOCK], terminal=True)
    assert b"755224" in shown and retry["revision"] == first["revision"]
    _, shown = command(["otp", hotp["id"]], [UNLOCK], terminal=True)
    assert b"287082" in shown

    codes, _ = command(["add", "recovery-codes", "--label", "codes", "--scope", "test"], [UNLOCK, "synthetic-recovery-code", ""])
    _, shown = command(["recovery-code", codes["id"]], [UNLOCK], terminal=True)
    assert b"synthetic-recovery-code" in shown
    command(["recovery-code", codes["id"]], [UNLOCK], terminal=True, succeeds=False)
    root_entry, _ = command(["add", "domain-root", "--label", "root", "--scope", "test"], [UNLOCK])
    command(["show", root_entry["id"]], [UNLOCK], terminal=True, succeeds=False)


with tempfile.TemporaryDirectory(prefix="vault-terminal-test-") as directory:
    exercise(Path(directory))
print("PASS: hidden entry, terminal-only reveal, HOTP exact retry, recovery-code consumption, root reveal denied")
