#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import pty
import re
import select
import signal
import sys
import time


def fail(message: str, transcript: bytearray, child: int | None = None) -> None:
    if child is not None:
        try:
            os.kill(child, signal.SIGTERM)
        except ProcessLookupError:
            pass
    sys.stderr.buffer.write(transcript)
    print(f"homed SSH audit failed: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 4:
    print("usage: homed-ssh-expect.py SSH_PORT PRIVATE_KEY PASSWORD", file=sys.stderr)
    raise SystemExit(2)

port, private_key, password = sys.argv[1:]
command = [
    "/usr/bin/ssh",
    "-tt",
    "-p",
    port,
    "-i",
    private_key,
    "-o",
    "BatchMode=no",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "ConnectTimeout=10",
    "particleadmin@127.0.0.1",
]

child, master = pty.fork()
if child == 0:
    os.execv(command[0], command)

transcript = bytearray()
deadline = time.monotonic() + 90
password_sent = False
command_sent = False
success_seen = False
marker = re.compile(rb"PARTICLEOS_HOMED_SSH_UNLOCK_PASS uid=[0-9]+ home=/home/particleadmin")

while time.monotonic() < deadline:
    readable, _, _ = select.select([master], [], [], 0.5)
    if readable:
        try:
            data = os.read(master, 65536)
        except OSError:
            data = b""
        if data:
            transcript.extend(data)
            lower = bytes(transcript).lower()
            if (
                not password_sent
                and b"please enter password for user particleadmin" in lower
            ):
                os.write(master, password.encode() + b"\n")
                password_sent = True
            if password_sent and not command_sent and (
                b"$ " in transcript or b"# " in transcript
            ):
                os.write(
                    master,
                    b"printf 'PARTICLEOS_HOMED_SSH_UNLOCK_PASS uid=%s home=%s\\n' "
                    b"\"$(id -u)\" \"$HOME\"; "
                    b"journalctl --boot --no-pager --output=cat _TRANSPORT=audit "
                    b"| grep -Eiq 'avc:.*denied.*(sshd|homed|homework|userdb|fallback)' "
                    b"&& printf 'PARTICLEOS_HOMED_SSH_AVC_FAIL\\n' "
                    b"|| printf 'PARTICLEOS_HOMED_SSH_AVC_PASS\\n'; exit\n",
                )
                command_sent = True
            if marker.search(transcript) and b"PARTICLEOS_HOMED_SSH_AVC_PASS" in transcript:
                success_seen = True
            if b"PARTICLEOS_HOMED_SSH_AVC_FAIL" in transcript:
                fail("SELinux denied the SSH/homed login path", transcript, child)

    finished, status = os.waitpid(child, os.WNOHANG)
    if finished:
        if success_seen and os.waitstatus_to_exitcode(status) == 0:
            sys.stdout.buffer.write(transcript)
            raise SystemExit(0)
        fail(
            f"SSH exited before proving unlock (status {os.waitstatus_to_exitcode(status)})",
            transcript,
        )

fail("timed out waiting for the homed unlock", transcript, child)
