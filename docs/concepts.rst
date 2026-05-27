General Concepts
================


Serializer vs Signer
--------------------

ItsDangerous provides two levels of data handling. The :doc:`/signer` is
the basic system that signs a given ``bytes`` value based on the given
signing parameters. The :doc:`/serializer` wraps a signer to enable
serializing and signing other data besides ``bytes``.

Typically, you'll want to use a serializer, not a signer. You can
configure the signing parameters through the serializer, and even
provide fallback signers to upgrade old tokens to new parameters.


The Secret Key
--------------

Signatures are secured by the ``secret_key``. Typically one secret key
is used with all signers, and the salt is used to distinguish different
contexts. Changing the secret key will invalidate existing tokens.

It should be a long random string of bytes. This value must be kept
secret and should not be saved in source code or committed to version
control. If an attacker learns the secret key, they can change and
resign data to look valid. If you suspect this happened, change the
secret key to invalidate existing tokens.

One way to keep the secret key separate is to read it from an
environment variable. When deploying for the first time, generate a key
and set the environment variable when running the application. All
process managers (like systemd) and hosting services have a way to
specify environment variables.

.. code-block:: python

    import os
    from itsdangerous.serializer import Serializer
    SECRET_KEY = os.environ.get("SECRET_KEY")
    s = Serializer(SECRET_KEY)

.. code-block:: text

    $ export SECRET_KEY="base64 encoded random bytes"
    $ python application.py

One way to generate a key is to use :func:`os.urandom`.

.. code-block:: text

    $ python3 -c 'import os; print(os.urandom(16).hex())'

.. warning::

    itsdangerous **signs** data but does not encrypt it. The payload is
    encoded (base64) but not secret — anyone who receives a token can
    decode and read its contents. Do not place sensitive data such as
    passwords or personally identifiable information inside a token unless
    you also encrypt it separately.

If you suspect your secret key has been compromised, replace it with a
single new key rather than appending to the rotation list. Passing a
list allows tokens signed by older keys to remain valid during the
overlap window — that is intentional for graceful rollover, but is the
wrong choice when you need to invalidate all existing tokens immediately.

Signed tokens are credentials: anyone who possesses a token can present
it for the lifetime of the signing key. Do not log token values, include
them in error responses, or expose them in places where unintended
parties can read them (for example, server-side access logs that capture
full URLs will capture any token embedded in a query string).


The Salt
--------

The salt is combined with the secret key to derive a unique key for
distinguishing different contexts. Unlike the secret key, the salt
doesn't have to be random, and can be saved in code. It only has to be
unique between contexts, not private.

For example, you want to email activation links to activate user
accounts, and upgrade links to upgrade users to a paid accounts. If all
you sign is the user id, and you don't use different salts, a user could
reuse the token from the activation link to upgrade the account. If you
use different salts, the signatures will be different and will not be
valid in the other context.

.. code-block:: python

    from itsdangerous.url_safe import URLSafeSerializer

    s1 = URLSafeSerializer("secret-key", salt="activate")
    s1.dumps(42)
    'NDI.MHQqszw6Wc81wOBQszCrEE_RlzY'

    s2 = URLSafeSerializer("secret-key", salt="upgrade")
    s2.dumps(42)
    'NDI.c0MpsD6gzpilOAeUPra3NShPXsE'

The second serializer can't load data dumped with the first because the
salts differ.

.. code-block:: python

    s2.loads(s1.dumps(42))
    Traceback (most recent call last):
      ...
    BadSignature: Signature does not match

Only the serializer with the same salt can load the data.

.. code-block:: python

    s2.loads(s2.dumps(42))
    42

.. warning::

    The salt is a **static, deterministic context label** — it is not
    per-token randomness and does not behave like a nonce or IV.
    Its sole purpose is to namespace signing keys so that tokens
    issued in one context cannot be replayed in another.

    Setting ``key_derivation="none"`` on a :class:`~itsdangerous.signer.Signer`
    disables key derivation entirely: the raw secret key is used as-is and the
    salt is **completely ignored**. Two signers that share the same secret key
    but use different salts will produce identical signatures, making the
    context-separation guarantee described above worthless. This mode is
    discouraged; use the default ``django-concat`` mode unless you have a
    specific reason to override it.


Key Rotation
------------

Key rotation can provide an extra layer of mitigation against an
attacker discovering a secret key. A rotation system will keep a list of
valid keys, generating a new key and removing the oldest key
periodically. If it takes four weeks for an attacker to crack a key, but
the key is rotated out after three weeks, they will not be able to use
any keys they crack. However, if a user doesn't refresh their token
within three weeks it will be invalid too.

The system that generates and maintains this list is outside the scope
of ItsDangerous, but ItsDangerous does support validating against a list
of keys.

Instead of passing a single key, you can pass a list of keys, oldest to
newest. When signing the last (newest) key will be used, and when
validating each key will be tried from newest to oldest before raising
a validation error.

.. code-block:: python

    SECRET_KEYS = ["2b9cd98e", "169d7886", "b6af09f5"]

    # sign some data with the latest key
    s = Serializer(SECRET_KEYS)
    t = s.dumps({"id": 42})

    # rotate a new key in and the oldest key out
    SECRET_KEYS.append("cf9b3588")
    del SECRET_KEYS[0]

    s = Serializer(SECRET_KEYS)
    s.loads(t)  # valid even though it was signed with a previous key

Note that :exc:`~itsdangerous.exc.SignatureExpired` is raised immediately
regardless of how many keys are in the rotation list. If a token's
timestamp has expired under the newest key, it is expired under every
key — itsdangerous does not try additional keys after a timeout failure.
Key rotation does not extend a token's lifetime.


.. _handling-exceptions:

Handling Exceptions
-------------------

All exceptions raised by itsdangerous inherit from
:exc:`~itsdangerous.exc.BadData`, which is the safe catch-all for any
verification failure. The hierarchy is:

-   :exc:`~itsdangerous.exc.BadData` — base class for all failures
-   :exc:`~itsdangerous.exc.BadSignature` — signature missing or does
    not match; subclass of ``BadData``; carries ``.payload``
-   :exc:`~itsdangerous.exc.BadTimeSignature` — timestamp is missing or
    malformed; subclass of ``BadSignature``; carries ``.payload`` and
    ``.date_signed``
-   :exc:`~itsdangerous.exc.SignatureExpired` — timestamp exceeded
    ``max_age``; subclass of ``BadTimeSignature``
-   :exc:`~itsdangerous.exc.BadHeader` — signed header is invalid;
    subclass of ``BadSignature``; carries ``.payload``, ``.header``, and
    ``.original_error``
-   :exc:`~itsdangerous.exc.BadPayload` — payload cannot be
    deserialized; subclass of ``BadData``; carries ``.original_error``

Catch :exc:`~itsdangerous.exc.BadData` (or a more specific subclass) and
treat every failure as an untrusted or expired token:

.. code-block:: python

    from itsdangerous import BadData

    try:
        data = s.loads(token)
    except BadData:
        # Treat as invalid: redirect to login, return 400/403, etc.
        ...

A few pitfalls to avoid:

-   **Do not surface exception details to users.**
    :exc:`~itsdangerous.exc.BadSignature` and its subclasses carry a
    ``payload`` attribute with the unverified decoded data;
    :exc:`~itsdangerous.exc.BadHeader` and
    :exc:`~itsdangerous.exc.BadPayload` also carry an ``original_error``
    attribute. Neither should be forwarded to the client or included in
    HTTP responses.
-   **Do not catch ``Exception`` broadly.** Swallowing ``BadData`` with a
    bare ``except Exception: pass`` silently turns a failed security check
    into a no-op.
-   **``BadTimeSignature.date_signed``** is available even when the
    signature is otherwise intact. It is useful for logging, but it comes
    from the token itself and must not be trusted for security decisions.


Digest Method Security
----------------------

A signer is configured with a ``digest_method``, a hash function that
is used as an intermediate step when generating the HMAC signature. The
default method is :func:`hashlib.sha1`. Occasionally, users are
concerned about this default because they have heard about hash
collisions with SHA-1.

When used as the intermediate, iterated step in HMAC, SHA-1 is not
insecure. In fact, even MD5 is still secure in HMAC. The security of the
hash alone doesn't apply when used in HMAC.

If a project considers SHA-1 a risk anyway, they can configure the
signer with a different digest method such as :func:`hashlib.sha512`.
A fallback signer for SHA-1 can be configured so that old tokens will be
upgraded. SHA-512 produces a longer hash, so tokens will take up more
space, which is relevant in cookies and URLs.
