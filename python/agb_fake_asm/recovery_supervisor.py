"""Minimal listener-side supervision for a replaceable policy worker."""

from __future__ import annotations

import json
import multiprocessing
import os
import select
import socket
import threading
from dataclasses import dataclass

from .enforcement_scope import enforcement_effect


def _worker_main(channel_fd: int, inherited_parent_fd: int) -> None:
    os.close(inherited_parent_fd)
    channel = socket.socket(fileno=channel_fd)
    try:
        while True:
            payload = channel.recv(4096)
            if not payload:
                return
            request = json.loads(payload)
            if request.get("crash"):
                os._exit(70)
            channel.send(json.dumps({"effect": request["effect"]}).encode())
    finally:
        channel.close()


@dataclass(frozen=True)
class SupervisedDecision:
    effect: str
    reason: str
    generation: int
    worker_restarted: bool


class RecoveringPolicyWorker:
    """Keep enforcement responsive while an optional policy worker restarts.

    The caller owns the seccomp listener. This class owns only a replaceable
    policy subprocess. Out-of-scope requests bypass that subprocess entirely.
    """

    def __init__(self, *, timeout_ms: float = 50, crash_first_target: bool = False) -> None:
        self.timeout_ms = timeout_ms
        self.generation = 0
        self._lock = threading.Lock()
        self._process: multiprocessing.Process | None = None
        self._channel: socket.socket | None = None
        self._crash_first_target = crash_first_target
        self._start()

    def _start(self) -> None:
        parent, child = socket.socketpair(type=socket.SOCK_SEQPACKET)
        context = multiprocessing.get_context("fork")
        process = context.Process(target=_worker_main, args=(child.fileno(), parent.fileno()), daemon=True)
        process.start()
        child.close()
        parent.setblocking(False)
        self._process = process
        self._channel = parent
        self.generation += 1

    def _stop(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        if self._process is not None:
            self._process.join(timeout=0.1)
            if self._process.is_alive():
                self._process.kill()
                self._process.join()
            self._process = None

    def close(self) -> None:
        with self._lock:
            self._stop()

    def decide(self, policy_effect: str, *, target: bool, crash: bool = False) -> SupervisedDecision:
        if not target:
            return SupervisedDecision("ALLOW", "EXECUTABLE_OUT_OF_SCOPE", self.generation, False)
        with self._lock:
            crash = crash or self._crash_first_target
            self._crash_first_target = False
            generation = self.generation
            try:
                assert self._channel is not None
                self._channel.send(json.dumps({"effect": policy_effect, "crash": crash}).encode())
                ready, _, _ = select.select([self._channel], [], [], self.timeout_ms / 1000)
                if not ready:
                    raise TimeoutError("policy worker response deadline exceeded")
                response = self._channel.recv(4096)
                if not response:
                    raise ConnectionError("policy worker exited")
                effect = json.loads(response)["effect"]
                return SupervisedDecision(effect, "POLICY_WORKER_OK", generation, False)
            except (BrokenPipeError, ConnectionError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
                self._stop()
                self._start()
                effect = enforcement_effect("ABSTAIN", target_pid=True, adapter_failed=True)
                return SupervisedDecision(effect, "POLICY_WORKER_RESTARTED_FAIL_CLOSED", self.generation, True)
