#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Answer the stable systemd first-boot prompts on a QEMU serial console."""

import os
import selectors
import signal
import subprocess
import sys
import time


PROMPTS = (
    (b"Please enter the new root password (empty to skip):", b"ParticleOS-Test-Root-261!\n"),
    (b"Please enter the new root password again:", b"ParticleOS-Test-Root-261!\n"),
    (b"Please enter the new timezone name or number", b"Etc/UTC\n"),
    (b"Please enter user name to create", b"particleadmin\n"),
    (b"Please enter new password for user particleadmin:", b"ParticleOS-Test-Run0-261!\n"),
    (b"Please enter new password for user particleadmin (repeat):", b"ParticleOS-Test-Run0-261!\n"),
    (b"login:", b"particleadmin\n"),
    (b"Password:", b"ParticleOS-Test-Run0-261!\n"),
    (
        b"PARTICLEOS_ADMIN_SHELL_READY",
        b"run0 --no-ask-password --pipe /usr/bin/true && "
        b"echo PARTICLEOS_FIRSTBOOT_CONSOLE_FAIL run0-accepted-without-auth || "
        b"echo PARTICLEOS_RUN0_NOAUTH_DENIED; "
        b"run0 --pipe /usr/bin/bash -c 'test \"$(/usr/bin/id -u)\" = 0 && "
        b"! /usr/sbin/ausearch -m AVC -ts boot 2>/dev/null | "
        b"/usr/bin/grep -Eiq \"homed|homework|fsadm|policykit|run0|login\" && "
        b"/usr/sbin/ausearch -m USER_AUTH,USER_ACCT -ts boot 2>/dev/null | "
        b"/usr/bin/grep -q \"acct=\\\"particleadmin\\\"\"' && "
        b"echo PARTICLEOS_FIRSTBOOT_CONSOLE_PASS "
        b"user=particleadmin timezone=Etc/UTC run0=authenticated; exit\n",
    ),
    (b"Password:", b"ParticleOS-Test-Run0-261!\n"),
)


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

    timeout = int(os.environ.get("FIRSTBOOT_VM_TIMEOUT", "300"))
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    pending = bytearray()
    prompt_index = 0
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

    try:
        with open(sys.argv[1], "wb") as log:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"QEMU exceeded {timeout}s")
                for key, _ in selector.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        continue
                    log.write(chunk)
                    log.flush()
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    transcript.extend(chunk)
                    pending.extend(chunk)
                    if prompt_index < len(PROMPTS):
                        prompt, answer = PROMPTS[prompt_index]
                        if prompt in pending:
                            if answer is not None:
                                process.stdin.write(answer)
                                process.stdin.flush()
                            prompt_index += 1
                            pending.clear()
            remainder = process.stdout.read()
            if remainder:
                log.write(remainder)
                sys.stdout.buffer.write(remainder)
                sys.stdout.buffer.flush()
                transcript.extend(remainder)
    except (BrokenPipeError, TimeoutError) as error:
        print(f"first-boot console automation failed: {error}", file=sys.stderr)
        stop(process)
        return 1
    finally:
        selector.close()

    if process.returncode != 0:
        print(f"QEMU exited with status {process.returncode}", file=sys.stderr)
        return 1
    if prompt_index != len(PROMPTS):
        missing = PROMPTS[prompt_index][0].decode()
        print(f"first-boot prompt was not observed: {missing}", file=sys.stderr)
        return 1
    if b"PARTICLEOS_FIRSTBOOT_CONSOLE_FAIL " in transcript:
        return 1
    if b"PARTICLEOS_RUN0_NOAUTH_DENIED" not in transcript:
        print("run0 did not report its unauthenticated denial", file=sys.stderr)
        return 1
    if b"PARTICLEOS_FIRSTBOOT_CONSOLE_PASS " not in transcript:
        print("first-boot guest audit did not report success", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
