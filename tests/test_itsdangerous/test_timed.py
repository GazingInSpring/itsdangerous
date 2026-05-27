from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_signer import TestSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin, TestSigner):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            signer.unsign(signed, max_age=10)

        assert exc_info.value.date_signed == ts

    def test_return_timestamp(self, signer, ts):
        signed = signer.sign("value")
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_future_age(self, signer):
        signed = signer.sign("value")

        with freeze_time("1971-05-31"):
            with pytest.raises(SignatureExpired) as exc_info:
                signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_sig_error_date_signed(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert isinstance(exc_info.value.date_signed, datetime)


class TestTimedSerializer(FreezeMixin, TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert serializer.load_payload(exc_info.value.payload) == value

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, return_timestamp=True) == (value, ts)

    def test_fallback_signers_not_expired(self, serializer_factory, value):
        """A token signed with the fallback algorithm loads successfully
        when max_age has not elapsed yet."""
        import hashlib

        # Sign the value using a SHA-256 serializer (this becomes the "old" format).
        sha256_serializer = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha256}
        )
        signed = sha256_serializer.dumps(value)

        # A new serializer uses SHA-512 as primary and SHA-256 as fallback.
        fallback_serializer = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha512},
            fallback_signers=[{"digest_method": hashlib.sha256}],
        )

        # Token was just signed, so max_age=10 is plenty — should succeed.
        assert fallback_serializer.loads(signed, max_age=10) == value

    def test_fallback_signers_expired(self, serializer_factory, value, freeze):
        """SignatureExpired is re-raised immediately when encountered inside
        the fallback loop — the loop does NOT continue to the next signer."""
        import hashlib

        # Sign the value using a SHA-256 serializer (this becomes the "old" format).
        sha256_serializer = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha256}
        )
        signed = sha256_serializer.dumps(value)

        # A new serializer uses SHA-512 as primary and SHA-256 as fallback.
        fallback_serializer = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha512},
            fallback_signers=[{"digest_method": hashlib.sha256}],
        )

        # Advance the clock past max_age so the token is expired.
        freeze.tick(timedelta(seconds=20))

        # The primary signer (SHA-512) will raise BadSignature because the
        # token was signed with SHA-256 — that is swallowed and the loop
        # continues to the fallback.  The fallback (SHA-256) verifies the
        # signature successfully but then sees the token is expired and raises
        # SignatureExpired.  The short-circuit in the loop must re-raise it
        # immediately instead of falling through to any further signer.
        with pytest.raises(SignatureExpired):
            fallback_serializer.loads(signed, max_age=10)
