from .compat import PY2, PY3
from .universaldetector import UniversalDetector
from .version import __version__, VERSION


def detect(byte_str):
    if not isinstance(byte_str, bytearray):
        if not isinstance(byte_str, bytes):
            raise TypeError('Expected object of type bytes or bytearray, got: '
                            '{0}'.format(type(byte_str)))
        else:
            byte_str = bytearray(byte_str)
    detector = UniversalDetector()
    detector.feed(byte_str)
    return detector.close()
