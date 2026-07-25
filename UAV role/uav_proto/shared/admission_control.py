"""Fail-closed replay and load admission for the resident UAV service."""

import collections
import threading
import time


class AdmissionError(ValueError):
    pass


class _Bucket:
    def __init__(self, rate: float, burst: float, now: float):
        self.rate = rate
        self.capacity = burst
        self.tokens = burst
        self.updated = now

    def take(self, now: float) -> bool:
        self.tokens = min(
            self.capacity, self.tokens + (now - self.updated) * self.rate
        )
        self.updated = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class AdmissionController:
    """Atomic bounds for unauthenticated work, replay state, and concurrency."""

    def __init__(self, *, global_rate: float = 8.0, global_burst: int = 16,
                 per_cert_rate: float = 2.0, per_cert_burst: int = 4,
                 pair_gap_seconds: float = 0.25, replay_ttl_seconds: int = 120,
                 replay_capacity: int = 4096, concurrent: int = 2):
        now = time.monotonic()
        self._lock = threading.Lock()
        self._global = _Bucket(global_rate, global_burst, now)
        self._per_cert_rate = per_cert_rate
        self._per_cert_burst = per_cert_burst
        self._cert_buckets = {}
        self._pair_last = {}
        self._replays = collections.OrderedDict()
        self._pair_gap = pair_gap_seconds
        self._replay_ttl = replay_ttl_seconds
        self._capacity = replay_capacity
        self._slots = threading.BoundedSemaphore(concurrent)

    def pre_auth(self) -> None:
        with self._lock:
            if not self._global.take(time.monotonic()):
                raise AdmissionError("global pre-authentication budget exhausted")

    def admit(self, cert_id: bytes, auth_ref: bytes, n_v: bytes,
              req_id: bytes) -> None:
        now = time.monotonic()
        replay_key = (cert_id, n_v, req_id)
        pair_key = (cert_id, auth_ref)
        with self._lock:
            cutoff = now - self._replay_ttl
            while self._replays and next(iter(self._replays.values())) < cutoff:
                self._replays.popitem(last=False)
            if replay_key in self._replays:
                raise AdmissionError("replayed verifier request")
            bucket = self._cert_buckets.get(cert_id)
            if bucket is None:
                bucket = _Bucket(
                    self._per_cert_rate, self._per_cert_burst, now
                )
                self._cert_buckets[cert_id] = bucket
            if not bucket.take(now):
                raise AdmissionError("per-certificate budget exhausted")
            previous = self._pair_last.get(pair_key)
            if previous is not None and now - previous < self._pair_gap:
                raise AdmissionError("certificate/pseudonym request gap violated")
            if not self._slots.acquire(blocking=False):
                raise AdmissionError("authentication worker queue is full")
            # State is consumed before expensive work and remains consumed if
            # that work later fails, preventing retry amplification.
            self._pair_last[pair_key] = now
            self._replays[replay_key] = now
            while len(self._replays) > self._capacity:
                self._replays.popitem(last=False)

    def release(self) -> None:
        self._slots.release()
