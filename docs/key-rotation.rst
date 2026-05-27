Key Rotation and Algorithm Migration
=====================================

Rotating secret keys and upgrading signing algorithms are routine
operational tasks for any application that issues long-lived tokens.
Both concerns are built into itsdangerous: the :class:`~itsdangerous.serializer.Serializer`
(and the underlying :class:`~itsdangerous.signer.Signer`) support a
list of secret keys for gradual key rotation, and a
``fallback_signers`` list that lets the application accept tokens
signed with an older algorithm while new tokens are issued with a
stronger one.

The two mechanisms are independent but compose cleanly — a single
serializer instance can rotate keys and migrate algorithms at the same
time without any extra bookkeeping.


Key Rotation
------------

Instead of accepting only a single ``secret_key``, both
:class:`~itsdangerous.serializer.Serializer` and
:class:`~itsdangerous.signer.Signer` accept a **list** of keys.  The
list should be ordered oldest to newest.  The keys are stored on the
instance as :attr:`~itsdangerous.signer.Signer.secret_keys`.

-   :meth:`~itsdangerous.serializer.Serializer.dumps` (signing) always
    uses ``secret_keys[-1]`` — the last, newest entry.
-   :meth:`~itsdangerous.serializer.Serializer.loads` (verification)
    tries every key, iterating from newest to oldest, and accepts the
    first one that produces a valid signature.

The canonical three-step rotation procedure is:

.. code-block:: python

    # Step 1 — original setup with a single key
    s = Serializer(secret_key="old-key")

    # Step 2 — introduce the new key by appending it to the end.
    # New tokens are signed with "new-key"; tokens that were already
    # signed with "old-key" continue to verify successfully.
    s = Serializer(secret_key=["old-key", "new-key"])

    # Step 3 — once all "old-key" tokens have expired or been
    # invalidated, remove the old key entirely.
    s = Serializer(secret_key=["new-key"])

.. note::

    No information about which key was actually used during
    verification is exposed to callers.  :meth:`~itsdangerous.serializer.Serializer.loads`
    returns the deserialized payload directly, and any
    :exc:`~itsdangerous.exc.BadSignature` raised when all keys have
    been exhausted does not indicate which key was closest to matching.


Algorithm Migration
-------------------

``fallback_signers`` lets you accept tokens that were signed with an
older algorithm while issuing all new tokens with a stronger one.  The
primary signer — configured via ``signer_kwargs`` on the serializer —
is always used by :meth:`~itsdangerous.serializer.Serializer.dumps`.
Fallback signers are consulted **only** during
:meth:`~itsdangerous.serializer.Serializer.loads`; they are never used
for signing.

Each entry in ``fallback_signers`` can take one of three forms:

.. code-block:: python

    import hashlib
    from itsdangerous import Serializer

    # 1. A dict — treated as signer_kwargs overrides; the primary
    #    signer class is kept.
    fallback_signers=[{"digest_method": hashlib.sha1}]

    # 2. A (signer_class, kwargs) tuple — uses the given class and
    #    kwargs directly.
    fallback_signers=[(MySigner, {"key_derivation": "hmac"})]

    # 3. A bare signer class — uses the primary signer_kwargs as-is.
    fallback_signers=[MySigner]

The canonical recipe for migrating from SHA-1 to SHA-512 is:

.. code-block:: python

    import hashlib
    from itsdangerous import Serializer

    # Phase 1: issue SHA-512 tokens; still accept old SHA-1 tokens.
    s = Serializer(
        secret_key="my-secret",
        signer_kwargs={"digest_method": hashlib.sha512},
        fallback_signers=[{"digest_method": hashlib.sha1}],
    )

    # Phase 2: once all SHA-1 tokens are drained, drop the fallback.
    s = Serializer(
        secret_key="my-secret",
        signer_kwargs={"digest_method": hashlib.sha512},
    )

During Phase 1, every call to ``dumps`` produces a SHA-512 token.
Every call to ``loads`` first tries SHA-512; if that fails it tries
SHA-1 before raising :exc:`~itsdangerous.exc.BadSignature`.


Combining Key Rotation and Algorithm Migration
----------------------------------------------

Both mechanisms work together without any additional configuration.
For example:

.. code-block:: python

    import hashlib
    from itsdangerous import Serializer

    s = Serializer(
        secret_key=["old-key", "new-key"],
        signer_kwargs={"digest_method": hashlib.sha512},
        fallback_signers=[{"digest_method": hashlib.sha1}],
    )

A call to ``loads`` will accept tokens from any of these four
combinations:

-   ``new-key`` + SHA-512 (current — signed by this serializer)
-   ``old-key`` + SHA-512 (previous key, current algorithm)
-   ``new-key`` + SHA-1 (current key, legacy algorithm)
-   ``old-key`` + SHA-1 (previous key, legacy algorithm)

Only the ``new-key`` + SHA-512 combination is ever produced by
``dumps``.

.. warning::

    The number of signer instances tried per ``loads`` call is
    ``1 + (len(secret_keys) × len(fallback_signers))``.  With two
    keys and one fallback entry that is three instances; with three
    keys and two fallback entries that is seven.  There is no caching
    between calls.  Keep both lists short to avoid a measurable
    performance impact on high-traffic endpoints.


How ``loads`` Iterates Signers
------------------------------

This section describes the internal mechanics for users who need to
debug or extend the fallback behaviour.

The iteration is performed by
:meth:`~itsdangerous.serializer.Serializer.iter_unsigners`, which
yields signer instances in order:

1.  **Primary signer** — constructed with the full ``secret_keys``
    list.  A single call to its
    :meth:`~itsdangerous.signer.Signer.verify_signature` method
    iterates over all keys internally (newest to oldest), so the
    primary signer accounts for only one iteration of the outer loop
    regardless of how many keys are in the list.

2.  **Fallback signers** — each entry in ``fallback_signers``
    generates **one signer instance per key** (not one signer with all
    keys).  Three keys and one fallback entry therefore produce three
    fallback signer objects.

The ``loads`` loop catches :exc:`~itsdangerous.exc.BadSignature` from
each signer and moves on to the next.  When the iterator is exhausted
it re-raises the **last** :exc:`~itsdangerous.exc.BadSignature`
encountered, not the first.

:exc:`~itsdangerous.exc.BadPayload` (corrupt payload body — invalid
JSON, bad zlib data, etc.) is **not** caught by the fallback loop.
If a signer successfully verifies the signature but the payload
cannot be deserialized, :exc:`~itsdangerous.exc.BadPayload` propagates
immediately without trying the remaining signers.


Timed Tokens and Expiry
-----------------------

:class:`~itsdangerous.timed.TimedSerializer` overrides ``loads`` to
add expiry checking via :class:`~itsdangerous.timed.TimestampSigner`.
The fallback loop behaves slightly differently for timed tokens:

-   If a signer verifies the signature successfully but the token is
    expired, :exc:`~itsdangerous.exc.SignatureExpired` is raised
    **immediately** — the loop does not try the remaining fallback
    signers.
-   Rationale: an expired token is expired regardless of which
    algorithm signed it.  Trying a weaker algorithm cannot
    un-expire a token.

This means that during an algorithm migration, expired tokens from the
old algorithm will raise :exc:`~itsdangerous.exc.SignatureExpired`
rather than :exc:`~itsdangerous.exc.BadSignature`.

The exception hierarchy for timed tokens is:

.. code-block:: text

    BadSignature
    └── BadTimeSignature
        └── SignatureExpired   ← hard-stops the fallback loop
    BadPayload                 ← also hard-stops (not caught at all)

:exc:`~itsdangerous.exc.SignatureExpired` carries a ``.payload``
attribute containing the decoded (but unverified) payload.  This is
useful for presenting a message such as "your session has expired,
please log in again" without allowing the expired data to be treated
as trusted.


Version History and the SHA-512 Default Change
-----------------------------------------------

The default digest method has changed across releases.  If you are
upgrading an application with existing tokens, the table below shows
what each release used and what fallback signers (if any) it shipped:

.. list-table::
    :header-rows: 1
    :widths: 20 25 55

    *   -   Version
        -   Default digest
        -   ``default_fallback_signers``
    *   -   < 1.0.0
        -   SHA-1
        -   ``[]``
    *   -   1.0.0 *(yanked)*
        -   SHA-512
        -   —
    *   -   1.1.0
        -   SHA-1 (reverted)
        -   ``[{"digest_method": hashlib.sha512}]``
    *   -   2.0.0+
        -   SHA-1
        -   ``[]`` (empty — **removed**)

**As of 2.0.0, ``default_fallback_signers`` is an empty list.**  The
SHA-512 fallback that was added in 1.1.0 to smooth the transition away
from the yanked 1.0.0 release was removed in 2.0.0 (:issue:`155`).

If your application still has tokens that were signed by the yanked
1.0.0 release (which used SHA-512 by default), you must add the
fallback manually:

.. code-block:: python

    import hashlib
    from itsdangerous import Serializer

    s = Serializer(
        secret_key="my-secret",
        fallback_signers=[{"digest_method": hashlib.sha512}],
    )

This configures the serializer to accept SHA-512-signed tokens during
``loads`` while continuing to issue (and verify by default) SHA-1-signed
tokens via ``dumps``.
