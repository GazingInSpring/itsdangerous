.. module:: itsdangerous.timed

Signing With Timestamps
=======================

If you want to expire signatures you can use the
:class:`TimestampSigner` class which adds timestamp information and
signs it. On unsigning you can validate that the timestamp is not older
than a given age.

:class:`TimestampSigner` signs raw bytes and embeds a timestamp — use it when you're already working with bytes and need expiry. :class:`TimedSerializer` wraps :class:`TimestampSigner` to handle arbitrary Python objects such as dicts and lists — use it when you want to sign structured data with an expiry. In general, if you're not already working with raw bytes, reach for :class:`TimedSerializer`.

.. code-block:: python

    from itsdangerous import TimestampSigner
    s = TimestampSigner('secret-key')
    string = s.sign('foo')

.. code-block:: python

    s.unsign(string, max_age=5)
    Traceback (most recent call last):
      ...
    itsdangerous.exc.SignatureExpired: Signature age 15 > 5 seconds

.. autoclass:: TimestampSigner
    :members:

.. autoclass:: TimedSerializer
    :members:
