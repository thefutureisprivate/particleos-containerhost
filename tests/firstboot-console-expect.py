#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Drive native first-boot setup on VGA and finish the login audit on serial."""

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT_PASSWORD = "VgaSetup261Secure"
ADMIN_PASSWORD = "VgaAdmin261Secure"

# Each entry contains required OCR fragments, forbidden fragments, and the
# response typed through QMP into the primary VGA virtual terminal.
VGA_PROMPTS = (
    (("enter the new root password", "empty to skip"), (), ROOT_PASSWORD),
    (("enter the new root password again",), (), ROOT_PASSWORD),
    (("enter the new timezone", "name or number"), (), "Etc/UTC"),
    (("enter user name", "create"), (), "particleadmin"),
    (("enter new password", "particleadmin"), ("repeat",), ADMIN_PASSWORD),
    (("enter new password", "particleadmin", "repeat"), (), ADMIN_PASSWORD),
)

SERIAL_PROMPTS = (
    (b"login:", b"particleadmin\n"),
    (b"Password:", f"{ADMIN_PASSWORD}\n".encode()),
    (
        b"PARTICLEOS_ADMIN_SHELL_READY",
        b"run0 --no-ask-password --pipe /usr/bin/true && exit 97 || "
        b"echo PARTICLEOS_RUN0_NOAUTH_DENIED; "
        b"run0 --pipe /usr/bin/bash /run/particleos-firstboot-run0-audit || { "
        b"echo PARTICLEOS_RUN0_AUTH_FAILED; "
        b"systemctl --no-pager --full status polkit.service systemd-homed.service "
        b"systemd-logind.service; "
        b"journalctl --boot --no-pager --output=short-monotonic "
        b"-u polkit.service -u systemd-homed.service -u systemd-logind.service; "
        b"journalctl --boot --no-pager --output=cat _TRANSPORT=audit | "
        b"grep -Ei '(avc:.*denied|polkit-agent-helper|unit=run-p|acct=.?particleadmin)'; "
        b"}; exit\n",
    ),
    (b"Password:", f"{ADMIN_PASSWORD}\n".encode()),
)


class QMP:
    """Minimal synchronous QEMU Machine Protocol client."""

    def __init__(self, path: str, deadline: float) -> None:
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.socket.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"QMP socket did not appear: {path}")
                time.sleep(0.05)
        self.stream = self.socket.makefile("rwb", buffering=0)
        greeting = self._read_message()
        if "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        self.execute("qmp_capabilities")

    def _read_message(self) -> dict[str, object]:
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            message = json.loads(line)
            if "event" not in message:
                return message

    def execute(self, command: str, arguments: dict[str, object] | None = None) -> object:
        request: dict[str, object] = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        response = self._read_message()
        if "error" in response:
            raise RuntimeError(f"QMP {command} failed: {response['error']!r}")
        return response.get("return")

    def key(self, qcode: str, shifted: bool = False) -> None:
        events: list[dict[str, object]] = []

        def event(code: str, down: bool) -> dict[str, object]:
            return {
                "type": "key",
                "data": {
                    "down": down,
                    "key": {"type": "qcode", "data": code},
                },
            }

        if shifted:
            events.append(event("shift", True))
        events.extend((event(qcode, True), event(qcode, False)))
        if shifted:
            events.append(event("shift", False))
        self.execute("input-send-event", {"events": events})
        time.sleep(0.015)

    def type_line(self, value: str) -> None:
        punctuation = {"/": ("slash", False), "-": ("minus", False)}
        for character in value:
            if character.isalpha() and character.isascii():
                self.key(character.lower(), character.isupper())
            elif character.isdigit():
                self.key(character)
            elif character in punctuation:
                self.key(*punctuation[character])
            else:
                raise ValueError(f"unsupported VGA input character: {character!r}")
        self.key("ret")

    def screenshot_text(self, screenshot: Path) -> str:
        self.execute("screendump", {"filename": str(screenshot)})
        result = subprocess.run(
            ["tesseract", str(screenshot), "stdout", "--psm", "6"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if result.returncode != 0:
            return ""
        text = " ".join(result.stdout.decode(errors="replace").lower().split())
        # VGA's bitmap font makes these two stable words look like a Latin
        # "u" to Tesseract. Normalize only the prompt vocabulary we assert.
        return text.replace("passuord", "password").replace("neu ", "new ")

    def close(self) -> None:
        self.stream.close()
        self.socket.close()


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print(f"usage: {sys.argv[0]} LOG -- QEMU [ARGUMENT ...]", file=sys.stderr)
        return 2

    qmp_path = os.environ.get("FIRSTBOOT_QMP_SOCKET")
    screenshot_path = os.environ.get("FIRSTBOOT_VGA_SCREENSHOT")
    if not qmp_path or not screenshot_path:
        print("FIRSTBOOT_QMP_SOCKET and FIRSTBOOT_VGA_SCREENSHOT are required", file=sys.stderr)
        return 2

    timeout = int(os.environ.get("FIRSTBOOT_VM_TIMEOUT", "420"))
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    pending = bytearray()
    serial_index = 0
    vga_index = 0
    firmware_entry_visible = False
    next_screenshot = 0.0
    process = subprocess.Popen(
        sys.argv[3:],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    qmp: QMP | None = None

    try:
        qmp = QMP(qmp_path, deadline)
        with open(sys.argv[1], "wb") as log:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"QEMU exceeded {timeout}s")

                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        continue
                    log.write(chunk)
                    log.flush()
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    transcript.extend(chunk)
                    pending.extend(chunk)
                    if serial_index < len(SERIAL_PROMPTS):
                        prompt, answer = SERIAL_PROMPTS[serial_index]
                        if prompt in pending:
                            if serial_index == len(SERIAL_PROMPTS) - 1:
                                time.sleep(0.5)
                            process.stdin.write(answer)
                            process.stdin.flush()
                            serial_index += 1
                            pending.clear()

                now = time.monotonic()
                if vga_index < len(VGA_PROMPTS) and now >= next_screenshot:
                    next_screenshot = now + 0.6
                    try:
                        screen = qmp.screenshot_text(Path(screenshot_path))
                    except (RuntimeError, subprocess.TimeoutExpired):
                        continue
                    if (
                        not firmware_entry_visible
                        and "reboot into" in screen
                        and "firmware interface" in screen
                    ):
                        firmware_entry_visible = True
                        print("SYSTEMD_BOOT_FIRMWARE_ENTRY_VISIBLE", flush=True)
                    required, forbidden, answer = VGA_PROMPTS[vga_index]
                    if all(fragment in screen for fragment in required) and not any(
                        fragment in screen for fragment in forbidden
                    ):
                        print(
                            "FIRSTBOOT_VGA_PROMPT_VISIBLE "
                            f"index={vga_index + 1} prompt={required[0]}",
                            flush=True,
                        )
                        qmp.type_line(answer)
                        vga_index += 1

            remainder = process.stdout.read()
            if remainder:
                log.write(remainder)
                sys.stdout.buffer.write(remainder)
                sys.stdout.buffer.flush()
                transcript.extend(remainder)
    except (BrokenPipeError, RuntimeError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"first-boot console automation failed: {error}", file=sys.stderr)
        stop(process)
        return 1
    finally:
        selector.close()
        if qmp is not None:
            qmp.close()

    if process.returncode != 0:
        print(f"QEMU exited with status {process.returncode}", file=sys.stderr)
        return 1
    if vga_index != len(VGA_PROMPTS):
        missing = VGA_PROMPTS[vga_index][0][0]
        print(f"VGA first-boot prompt was not observed: {missing}", file=sys.stderr)
        return 1
    if not firmware_entry_visible:
        print("reboot-into-firmware entry was not visible on VGA", file=sys.stderr)
        return 1
    if serial_index != len(SERIAL_PROMPTS):
        missing = SERIAL_PROMPTS[serial_index][0].decode()
        print(f"serial login prompt was not observed: {missing}", file=sys.stderr)
        return 1
    if b"PARTICLEOS_FIRSTBOOT_CONSOLE_FAIL " in transcript:
        return 1
    if b"PARTICLEOS_RUN0_NOAUTH_DENIED" not in transcript:
        print("run0 did not report its unauthenticated denial", file=sys.stderr)
        return 1
    if b"==== AUTHENTICATION COMPLETE ====" not in transcript:
        print("run0 did not complete its interactive authentication", file=sys.stderr)
        return 1
    if b"PARTICLEOS_FIRSTBOOT_CONSOLE_PASS " not in transcript:
        print("first-boot guest audit did not report success", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
