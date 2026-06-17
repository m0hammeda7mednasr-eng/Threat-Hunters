try:
    import cPickle as pickle
except:
    import pickle

import base64
import binascii
import codecs
import json
import re
import sys
import time

from lib.core.bigarray import BigArray
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.settings import INVALID_UNICODE_PRIVATE_AREA
from lib.core.settings import IS_TTY
from lib.core.settings import IS_WIN
from lib.core.settings import NULL
from lib.core.settings import PICKLE_PROTOCOL
from lib.core.settings import SAFE_HEX_MARKER
from lib.core.settings import UNICODE_ENCODING
from thirdparty import six
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import html_parser
from thirdparty.six.moves import collections_abc as _collections

try:
    from html import escape as htmlEscape
except ImportError:
    from cgi import escape as htmlEscape

def base64pickle(value):

    retVal = None

    try:
        retVal = encodeBase64(pickle.dumps(value, PICKLE_PROTOCOL), binary=False)
    except:
        warnMsg = "problem occurred while serializing "
        warnMsg += "instance of a type '%s'" % type(value)
        singleTimeWarnMessage(warnMsg)

        try:
            retVal = encodeBase64(pickle.dumps(value), binary=False)
        except:
            raise

    return retVal

def base64unpickle(value):

    retVal = None

    try:
        retVal = pickle.loads(decodeBase64(value))
    except TypeError:
        retVal = pickle.loads(decodeBase64(bytes(value)))

    return retVal

def htmlUnescape(value):

    if value and isinstance(value, six.string_types):
        if six.PY3:
            import html
            return html.unescape(value)
        else:
            return html_parser.HTMLParser().unescape(value)
    return value

def singleTimeWarnMessage(message):  # Cross-referenced function
    sys.stdout.write(message)
    sys.stdout.write("\n")
    sys.stdout.flush()

def filterNone(values):  # Cross-referenced function
    return [_ for _ in values if _] if isinstance(values, _collections.Iterable) else values

def isListLike(value):  # Cross-referenced function
    return isinstance(value, (list, tuple, set, BigArray))

def shellExec(cmd):  # Cross-referenced function
    raise NotImplementedError

def jsonize(data):

    return json.dumps(data, sort_keys=False, indent=4)

def dejsonize(data):

    return json.loads(data)

def decodeHex(value, binary=True):

    retVal = value

    if isinstance(value, six.binary_type):
        value = getText(value)

    if value.lower().startswith("0x"):
        value = value[2:]

    try:
        retVal = codecs.decode(value, "hex")
    except LookupError:
        retVal = binascii.unhexlify(value)

    if not binary:
        retVal = getText(retVal)

    return retVal

def encodeHex(value, binary=True):

    if isinstance(value, int):
        value = six.int2byte(value)

    if isinstance(value, six.text_type):
        value = value.encode(UNICODE_ENCODING)

    try:
        retVal = codecs.encode(value, "hex")
    except LookupError:
        retVal = binascii.hexlify(value)

    if not binary:
        retVal = getText(retVal)

    return retVal

def decodeBase64(value, binary=True, encoding=None):

    if value is None:
        return None

    padding = b'=' if isinstance(value, bytes) else '='

    if not value.endswith(padding):
        value += 3 * padding

    if isinstance(value, bytes):
        value = value.replace(b'-', b'+').replace(b'_', b'/')
    else:
        value = value.replace('-', '+').replace('_', '/')

    retVal = base64.b64decode(value)

    if not binary:
        retVal = getText(retVal, encoding)

    return retVal

def encodeBase64(value, binary=True, encoding=None, padding=True, safe=False):

    if value is None:
        return None

    if isinstance(value, six.text_type):
        value = value.encode(encoding or UNICODE_ENCODING)

    retVal = base64.b64encode(value)

    if not binary:
        retVal = getText(retVal, encoding)

    if safe:
        padding = False

        if isinstance(retVal, bytes):
            retVal = retVal.replace(b'+', b'-').replace(b'/', b'_')
        else:
            retVal = retVal.replace('+', '-').replace('/', '_')

    if not padding:
        retVal = retVal.rstrip(b'=' if isinstance(retVal, bytes) else '=')

    return retVal

def getBytes(value, encoding=None, errors="strict", unsafe=True):

    retVal = value

    if encoding is None:
        encoding = conf.get("encoding") or UNICODE_ENCODING

    try:
        codecs.lookup(encoding)
    except (LookupError, TypeError):
        encoding = UNICODE_ENCODING

    if isinstance(value, bytearray):
        return bytes(value)
    elif isinstance(value, memoryview):
        return value.tobytes()
    elif isinstance(value, six.text_type):
        if INVALID_UNICODE_PRIVATE_AREA:
            if unsafe:
                for char in xrange(0xF0000, 0xF00FF + 1):
                    value = value.replace(_unichr(char), "%s%02x" % (SAFE_HEX_MARKER, char - 0xF0000))

            retVal = value.encode(encoding, errors)

            if unsafe:
                retVal = re.sub((r"%s([0-9a-f]{2})" % SAFE_HEX_MARKER).encode(), lambda _: decodeHex(_.group(1)), retVal)
        else:
            try:
                retVal = value.encode(encoding, errors)
            except UnicodeError:
                retVal = value.encode(UNICODE_ENCODING, errors="replace")

            if unsafe:
                retVal = re.sub(b"\\\\x([0-9a-f]{2})", lambda _: decodeHex(_.group(1)), retVal)

    return retVal

def getOrds(value):

    return [_ if isinstance(_, int) else ord(_) for _ in value]

def getUnicode(value, encoding=None, noneToNull=False):

    if conf.get("timeLimit") and kb.get("startTime") and (time.time() - kb.startTime > conf.timeLimit):
        raise SystemExit

    if noneToNull and value is None:
        return NULL

    if isinstance(value, six.text_type):
        return value
    elif isinstance(value, six.binary_type):
        candidates = filterNone((encoding, kb.get("pageEncoding") if kb.get("originalPage") else None, conf.get("encoding"), UNICODE_ENCODING, sys.getfilesystemencoding()))
        if all(_ in value for _ in (b'<', b'>')):
            pass
        elif b'\n' not in value and re.search(r"(?i)\w+\.\w{2,3}\Z|\A(\w:\\|/\w+)", six.text_type(value, UNICODE_ENCODING, errors="ignore")):
            candidates = filterNone((encoding, sys.getfilesystemencoding(), kb.get("pageEncoding") if kb.get("originalPage") else None, UNICODE_ENCODING, conf.get("encoding")))
        elif conf.get("encoding") and b'\n' not in value:
            candidates = filterNone((encoding, conf.get("encoding"), kb.get("pageEncoding") if kb.get("originalPage") else None, sys.getfilesystemencoding(), UNICODE_ENCODING))

        for candidate in candidates:
            try:
                return six.text_type(value, candidate)
            except (UnicodeDecodeError, LookupError):
                pass

        try:
            return six.text_type(value, encoding or (kb.get("pageEncoding") if kb.get("originalPage") else None) or UNICODE_ENCODING)
        except UnicodeDecodeError:
            return six.text_type(value, UNICODE_ENCODING, errors="reversible")
    elif isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    else:
        try:
            return six.text_type(value)
        except UnicodeDecodeError:
            return six.text_type(str(value), errors="ignore")  # encoding ignored for non-basestring instances

def getText(value, encoding=None):

    retVal = value

    if isinstance(value, six.binary_type):
        retVal = getUnicode(value, encoding)

    if six.PY2:
        try:
            retVal = str(retVal)
        except:
            pass

    return retVal

def stdoutEncode(value):

    if value is None:
        value = ""

    if IS_WIN and IS_TTY and kb.get("codePage", -1) is None:
        output = shellExec("chcp")
        match = re.search(r": (\d{3,})", output or "")

        if match:
            try:
                candidate = "cp%s" % match.group(1)
                codecs.lookup(candidate)
                kb.codePage = candidate
            except (LookupError, TypeError):
                pass

        kb.codePage = kb.codePage or ""

    encoding = kb.get("codePage") or getattr(sys.stdout, "encoding", None) or UNICODE_ENCODING

    if six.PY3:
        if isinstance(value, (bytes, bytearray)):
            value = getUnicode(value, encoding)
        elif not isinstance(value, str):
            value = str(value)

        try:
            retVal = value.encode(encoding, errors="replace").decode(encoding, errors="replace")
        except (LookupError, TypeError):
            retVal = value.encode("ascii", errors="replace").decode("ascii", errors="replace")
    else:
        if isinstance(value, six.text_type):
            try:
                retVal = value.encode(encoding, errors="replace")
            except (LookupError, TypeError):
                retVal = value.encode("ascii", errors="replace")
        else:
            retVal = value

    return retVal

def getConsoleLength(value):

    if isinstance(value, six.text_type):
        retVal = len(value) + sum(ord(_) >= 0x3000 for _ in value)
    else:
        retVal = len(value)

    return retVal
