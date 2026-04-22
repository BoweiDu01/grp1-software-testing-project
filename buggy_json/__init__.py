r"""JSON (JavaScript Object Notation) <https://json.org> is a subset of
JavaScript syntax (ECMA-262 3rd edition) used as a lightweight data
interchange format.

:mod:`json` exposes an API familiar to users of the standard library
:mod:`marshal` and :mod:`pickle` modules.  It is derived from a
version of the externally maintained simplejson library.

Decoding JSON::

    >>> import json
    >>> obj = ['foo', {'bar': ['baz', None, 1.0, 2]}]
    >>> json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]') == obj
    True
    >>> json.loads('"\\"foo\\bar"') == '"foo\x08ar'
    True

Specializing JSON object decoding::

    >>> import json
    >>> def as_complex(dct):
    ...     if '__complex__' in dct:
    ...         return complex(dct['real'], dct['imag'])
    ...     return dct
    ...
    >>> json.loads('{"__complex__": true, "real": 1, "imag": 2}',
    ...     object_hook=as_complex)
    (1+2j)
    >>> from decimal import Decimal
    >>> json.loads('1.1', parse_float=Decimal) == Decimal('1.1')
    True


Using json from the shell to validate and pretty-print::

    $ echo '{"json":"obj"}' | python -m json
    {
        "json": "obj"
    }
    $ echo '{ 1.2:3.4}' | python -m json
    Expecting property name enclosed in double quotes: line 1 column 3 (char 2)
"""
__version__ = '2.0.9'
__all__ = [
    'loads',
    'JSONDecoder', 'JSONDecodeError' 
]


__author__ = 'Bob Ippolito <bob@redivi.com>'

from .decoder_stv import JSONDecoder, JSONDecodeError
import codecs

_default_decoder = JSONDecoder(object_hook=None, object_pairs_hook=None)

def detect_encoding(b):
    bstartswith = b.startswith
    if bstartswith((codecs.BOM_UTF32_BE, codecs.BOM_UTF32_LE)):
        return 'utf-32'
    if bstartswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
        return 'utf-16'
    if bstartswith(codecs.BOM_UTF8):
        return 'utf-8-sig'

    if len(b) >= 4:
        if not b[0]:
            # 00 00 -- -- - utf-32-be
            # 00 XX -- -- - utf-16-be
            return 'utf-16-be' if b[1] else 'utf-32-be'
        if not b[1]:
            # XX 00 00 00 - utf-32-le
            # XX 00 00 XX - utf-16-le
            # XX 00 XX -- - utf-16-le
            return 'utf-16-le' if b[2] or b[3] else 'utf-32-le'
    elif len(b) == 2:
        if not b[0]:
            # 00 XX - utf-16-be
            return 'utf-16-be'
        if not b[1]:
            # XX 00 - utf-16-le
            return 'utf-16-le'
    # default
    return 'utf-8'

def loads(s, *, cls=None, object_hook=None, parse_float=None,
        parse_int=None, parse_constant=None, object_pairs_hook=None, **kw):
    """Deserialize ``s`` (a ``str``, ``bytes`` or ``bytearray`` instance
    containing a JSON document) to a Python object.

    ``object_hook`` is an optional function that will be called with the
    result of any object literal decode (a ``dict``). The return value of
    ``object_hook`` will be used instead of the ``dict``. This feature
    can be used to implement custom decoders (e.g. JSON-RPC class hinting).

    ``object_pairs_hook`` is an optional function that will be called with
    the result of any object literal decoded with an ordered list of pairs.
    The return value of ``object_pairs_hook`` will be used instead of the
    ``dict``.  This feature can be used to implement custom decoders.  If
    ``object_hook`` is also defined, the ``object_pairs_hook`` takes
    priority.

    ``parse_float``, if specified, will be called with the string
    of every JSON float to be decoded. By default this is equivalent to
    float(num_str). This can be used to use another datatype or parser
    for JSON floats (e.g. decimal.Decimal).

    ``parse_int``, if specified, will be called with the string
    of every JSON int to be decoded. By default this is equivalent to
    int(num_str). This can be used to use another datatype or parser
    for JSON integers (e.g. float).

    ``parse_constant``, if specified, will be called with one of the
    following strings: -Infinity, Infinity, NaN.
    This can be used to raise an exception if invalid JSON numbers
    are encountered.

    To use a custom ``JSONDecoder`` subclass, specify it with the ``cls``
    kwarg; otherwise ``JSONDecoder`` is used.
    """
    if isinstance(s, str):
        if s.startswith('\ufeff'):
            raise JSONDecodeError("Unexpected UTF-8 BOM (decode using utf-8-sig)",
                                  s, 0)
    else:
        if not isinstance(s, (bytes, bytearray)):
            raise TypeError(f'the JSON object must be str, bytes or bytearray, '
                            f'not {s.__class__.__name__}')
        s = s.decode(detect_encoding(s), 'surrogatepass')

    if (cls is None and object_hook is None and
            parse_int is None and parse_float is None and
            parse_constant is None and object_pairs_hook is None and not kw):
        return _default_decoder.decode(s)
    if cls is None:
        cls = JSONDecoder
    if object_hook is not None:
        kw['object_hook'] = object_hook
    if object_pairs_hook is not None:
        kw['object_pairs_hook'] = object_pairs_hook
    if parse_float is not None:
        kw['parse_float'] = parse_float
    if parse_int is not None:
        kw['parse_int'] = parse_int
    if parse_constant is not None:
        kw['parse_constant'] = parse_constant
    return cls(**kw).decode(s)
