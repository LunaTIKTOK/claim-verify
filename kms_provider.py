from __future__ import annotations

import hashlib
import hmac


class KMSProvider:
    def sign(self, payload_bytes: bytes) -> str:
        raise NotImplementedError

    def verify(self, payload_bytes: bytes, signature: str) -> bool:
        raise NotImplementedError

    def key_id(self) -> str:
        raise NotImplementedError


class DevHMACProvider(KMSProvider):
    def __init__(self, secret: bytes = b'dev-secret', kid: str = 'dev-hmac-key') -> None:
        self._secret = secret
        self._kid = kid

    def sign(self, payload_bytes: bytes) -> str:
        return hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()

    def verify(self, payload_bytes: bytes, signature: str) -> bool:
        expected = self.sign(payload_bytes)
        return hmac.compare_digest(expected, signature)

    def key_id(self) -> str:
        return self._kid


class MockKMSProvider(KMSProvider):
    def __init__(self, kid: str = 'mock-kms-key') -> None:
        self._kid = kid

    def sign(self, payload_bytes: bytes) -> str:
        return hashlib.sha256(b'mock:' + payload_bytes).hexdigest()

    def verify(self, payload_bytes: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload_bytes), signature)

    def key_id(self) -> str:
        return self._kid
