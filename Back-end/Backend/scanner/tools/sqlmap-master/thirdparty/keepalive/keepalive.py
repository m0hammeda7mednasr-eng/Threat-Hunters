from __future__ import print_function

try:
    from thirdparty.six.moves import http_client as _http_client
    from thirdparty.six.moves import range as _range
    from thirdparty.six.moves import urllib as _urllib
except ImportError:
    from six.moves import http_client as _http_client
    from six.moves import range as _range
    from six.moves import urllib as _urllib

import socket
import threading

DEBUG = None

import sys
if sys.version_info < (2, 4): HANDLE_ERRORS = 1
else: HANDLE_ERRORS = 0

class ConnectionManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._hostmap = {} # map hosts to a list of connections
        self._connmap = {} # map connections to host
        self._readymap = {} # map connection to ready state

    def add(self, host, connection, ready):
        self._lock.acquire()
        try:
            if host not in self._hostmap: self._hostmap[host] = []
            self._hostmap[host].append(connection)
            self._connmap[connection] = host
            self._readymap[connection] = ready
        finally:
            self._lock.release()

    def remove(self, connection):
        self._lock.acquire()
        try:
            try:
                host = self._connmap[connection]
            except KeyError:
                pass
            else:
                del self._connmap[connection]
                del self._readymap[connection]
                try:
                    self._hostmap[host].remove(connection)
                except ValueError:
                    pass
                if not self._hostmap[host]: del self._hostmap[host]
        finally:
            self._lock.release()

    def set_ready(self, connection, ready):
        self._lock.acquire()
        try:
            if connection in self._readymap: self._readymap[connection] = ready
        finally:
            self._lock.release()

    def get_ready_conn(self, host):
        conn = None
        try:
            self._lock.acquire()
            if host in self._hostmap:
                for c in self._hostmap[host]:
                    if self._readymap.get(c):
                        self._readymap[c] = 0
                        conn = c
                        break
        finally:
            self._lock.release()
        return conn

    def get_all(self, host=None):
        self._lock.acquire()
        try:
            if host:
                return list(self._hostmap.get(host, []))
            else:
                return dict(self._hostmap)
        finally:
            self._lock.release()

class KeepAliveHandler:
    def __init__(self):
        self._cm = ConnectionManager()

    def open_connections(self):
        return [(host, len(li)) for (host, li) in self._cm.get_all().items()]

    def close_connection(self, host):
        for h in self._cm.get_all(host):
            self._cm.remove(h)
            h.close()

    def close_all(self):
        for host, conns in self._cm.get_all().items():
            for h in conns:
                self._cm.remove(h)
                h.close()

    def _request_closed(self, request, host, connection):
        self._cm.set_ready(connection, 1)

    def _remove_connection(self, host, connection, close=0):
        if close: connection.close()
        self._cm.remove(connection)

    def do_open(self, req):
        host = req.host
        if not host:
            raise _urllib.error.URLError('no host given')

        try:
            h = self._cm.get_ready_conn(host)
            while h:
                r = self._reuse_connection(h, req, host)

                if r: break

                h.close()
                self._cm.remove(h)
                h = self._cm.get_ready_conn(host)
            else:
                h = self._get_connection(host)
                if DEBUG: DEBUG.info("creating new connection to %s (%d)",
                                     host, id(h))
                self._start_transaction(h, req)
                r = h.getresponse()
                self._cm.add(host, h, 0)
        except (socket.error, _http_client.HTTPException) as err:
            raise _urllib.error.URLError(err)

        if DEBUG: DEBUG.info("STATUS: %s, %s", r.status, r.reason)

        if not r.will_close:
            try:
                headers = getattr(r, 'msg', None)
                if headers:
                    c_head = headers.get("connection")
                    if c_head and "close" in c_head.lower():
                        r.will_close = True
            except Exception:
                pass

        if r.will_close:
            if DEBUG: DEBUG.info('server will close connection, discarding')
            self._cm.remove(h)
            h.close()

        r._handler = self
        r._host = host
        r._url = req.get_full_url()
        r._connection = h
        r.code = r.status
        r.headers = r.msg

        if r.status == 200 or not HANDLE_ERRORS:
            return r
        else:
            return self.parent.error('http', req, r,
                                     r.status, r.reason, r.headers)

    def _reuse_connection(self, h, req, host):
        try:
            self._start_transaction(h, req)
            r = h.getresponse()
        except (socket.error, _http_client.HTTPException):
            r = None
        except Exception:
            if DEBUG: DEBUG.error("unexpected exception - closing " + \
                                  "connection to %s (%d)", host, id(h))
            self._cm.remove(h)
            h.close()
            raise

        if r is None or r.version == 9:
            if DEBUG: DEBUG.info("failed to re-use connection to %s (%d)",
                                 host, id(h))
            r = None
        else:
            if DEBUG: DEBUG.info("re-using connection to %s (%d)", host, id(h))

        return r

    def _start_transaction(self, h, req):
        try:
            if req.data:
                data = req.data
                if hasattr(req, 'selector'):
                    h.putrequest(req.get_method() or 'POST', req.selector, skip_host=req.has_header("Host"), skip_accept_encoding=req.has_header("Accept-encoding"))
                else:
                    h.putrequest(req.get_method() or 'POST', req.get_selector(), skip_host=req.has_header("Host"), skip_accept_encoding=req.has_header("Accept-encoding"))
                if 'Content-type' not in req.headers:
                    h.putheader('Content-type',
                                'application/x-www-form-urlencoded')
                if 'Content-length' not in req.headers:
                    h.putheader('Content-length', '%d' % len(data))
            else:
                if hasattr(req, 'selector'):
                    h.putrequest(req.get_method() or 'GET', req.selector, skip_host=req.has_header("Host"), skip_accept_encoding=req.has_header("Accept-encoding"))
                else:
                    h.putrequest(req.get_method() or 'GET', req.get_selector(), skip_host=req.has_header("Host"), skip_accept_encoding=req.has_header("Accept-encoding"))
        except (socket.error, _http_client.HTTPException) as err:
            raise _urllib.error.URLError(err)

        if 'Connection' not in req.headers:
            h.putheader('Connection', 'keep-alive')

        for args in self.parent.addheaders:
            if args[0] not in req.headers:
                h.putheader(*args)
        for k, v in req.headers.items():
            h.putheader(k, v)
        h.endheaders()
        if req.data:
            h.send(req.data)

    def _get_connection(self, host):
        raise NotImplementedError()

class HTTPHandler(KeepAliveHandler, _urllib.request.HTTPHandler):
    def __init__(self):
        KeepAliveHandler.__init__(self)

    def http_open(self, req):
        return self.do_open(req)

    def _get_connection(self, host):
        return HTTPConnection(host)

class HTTPSHandler(KeepAliveHandler, _urllib.request.HTTPSHandler):
    def __init__(self, ssl_factory=None):
        KeepAliveHandler.__init__(self)
        if not ssl_factory:
            try:
                import sslfactory
                ssl_factory = sslfactory.get_factory()
            except ImportError:
                pass
        self._ssl_factory = ssl_factory

    def https_open(self, req):
        return self.do_open(req)

    def _get_connection(self, host):
        if self._ssl_factory:
            return self._ssl_factory.get_https_connection(host)
        else:
            return HTTPSConnection(host)

class HTTPResponse(_http_client.HTTPResponse):




    def __init__(self, sock, debuglevel=0, strict=0, method=None):
        if method:
            _http_client.HTTPResponse.__init__(self, sock, debuglevel, method=method)
        else:
            _http_client.HTTPResponse.__init__(self, sock, debuglevel)
        self.fileno = sock.fileno
        self.code = None
        self._method = method
        self._rbuf = b""
        self._rbufsize = 8096
        self._handler = None # inserted by the handler later
        self._host = None    # (same)
        self._url = None     # (same)
        self._connection = None # (same)

    _raw_read = _http_client.HTTPResponse.read

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None
            if self._handler:
                self._handler._request_closed(self, self._host,
                                              self._connection)

    def _close_conn(self):
        self.close()

    def close_connection(self):
        self._handler._remove_connection(self._host, self._connection, close=1)
        self.close()

    def info(self):
        return self.headers

    def geturl(self):
        return self._url

    def read(self, amt=None):
        if self._rbuf and not amt is None:
            L = len(self._rbuf)
            if amt > L:
                amt -= L
            else:
                s = self._rbuf[:amt]
                self._rbuf = self._rbuf[amt:]
                return s

        s = self._rbuf + self._raw_read(amt)
        self._rbuf = b""
        return s

    def readline(self, limit=-1):
        data = b""
        i = self._rbuf.find(b'\n')
        while i < 0 and not (0 < limit <= len(self._rbuf)):
            new = self._raw_read(self._rbufsize)
            if not new: break
            i = new.find(b'\n')
            if i >= 0: i = i + len(self._rbuf)
            self._rbuf = self._rbuf + new
        if i < 0: i = len(self._rbuf)
        else: i = i+1
        if 0 <= limit < len(self._rbuf): i = limit
        data, self._rbuf = self._rbuf[:i], self._rbuf[i:]
        return data

    def readlines(self, sizehint = 0):
        total = 0
        lines = []
        while 1:
            line = self.readline()
            if not line: break
            lines.append(line)
            total += len(line)
            if sizehint and total >= sizehint:
                break
        return lines


class HTTPConnection(_http_client.HTTPConnection):
    response_class = HTTPResponse

class HTTPSConnection(_http_client.HTTPSConnection):
    response_class = HTTPResponse


def error_handler(url):
    global HANDLE_ERRORS
    orig = HANDLE_ERRORS
    keepalive_handler = HTTPHandler()
    opener = _urllib.request.build_opener(keepalive_handler)
    _urllib.request.install_opener(opener)
    pos = {0: 'off', 1: 'on'}
    for i in (0, 1):
        print("  fancy error handling %s (HANDLE_ERRORS = %i)" % (pos[i], i))
        HANDLE_ERRORS = i
        try:
            fo = _urllib.request.urlopen(url)
            foo = fo.read()
            fo.close()
            try: status, reason = fo.status, fo.reason
            except AttributeError: status, reason = None, None
        except IOError as e:
            print("  EXCEPTION: %s" % e)
            raise
        else:
            print("  status = %s, reason = %s" % (status, reason))
    HANDLE_ERRORS = orig
    hosts = keepalive_handler.open_connections()
    print("open connections:", hosts)
    keepalive_handler.close_all()

def continuity(url):
    from hashlib import md5
    format = '%25s: %s'

    opener = _urllib.request.build_opener()
    _urllib.request.install_opener(opener)
    fo = _urllib.request.urlopen(url)
    foo = fo.read()
    fo.close()
    m = md5(foo)
    print(format % ('normal urllib', m.hexdigest()))

    opener = _urllib.request.build_opener(HTTPHandler())
    _urllib.request.install_opener(opener)

    fo = _urllib.request.urlopen(url)
    foo = fo.read()
    fo.close()
    m = md5(foo)
    print(format % ('keepalive read', m.hexdigest()))

    fo = _urllib.request.urlopen(url)
    foo = b''
    while 1:
        f = fo.readline()
        if f: foo += f
        else: break
    fo.close()
    m = md5(foo)
    print(format % ('keepalive readline', m.hexdigest()))

def comp(N, url):
    print('  making %i connections to:\n  %s' % (N, url))

    sys.stdout.write('  first using the normal urllib handlers')
    opener = _urllib.request.build_opener()
    _urllib.request.install_opener(opener)
    t1 = fetch(N, url)
    print('  TIME: %.3f s' % t1)

    sys.stdout.write('  now using the keepalive handler       ')
    opener = _urllib.request.build_opener(HTTPHandler())
    _urllib.request.install_opener(opener)
    t2 = fetch(N, url)
    print('  TIME: %.3f s' % t2)
    print('  improvement factor: %.2f' % (t1/t2, ))

def fetch(N, url, delay=0):
    import time
    lens = []
    starttime = time.time()
    for i in _range(N):
        if delay and i > 0: time.sleep(delay)
        fo = _urllib.request.urlopen(url)
        foo = fo.read()
        fo.close()
        lens.append(len(foo))
    diff = time.time() - starttime

    j = 0
    for i in lens[1:]:
        j = j + 1
        if not i == lens[0]:
            print("WARNING: inconsistent length on read %i: %i" % (j, i))

    return diff

def test_timeout(url):
    global DEBUG
    dbbackup = DEBUG
    class FakeLogger:
        def debug(self, msg, *args): print(msg % args)
        info = warning = error = debug
    DEBUG = FakeLogger()
    print("  fetching the file to establish a connection")
    fo = _urllib.request.urlopen(url)
    data1 = fo.read()
    fo.close()

    i = 20
    print("  waiting %i seconds for the server to close the connection" % i)
    while i > 0:
        sys.stdout.write('\r  %2i' % i)
        sys.stdout.flush()
        time.sleep(1)
        i -= 1
    sys.stderr.write('\r')

    print("  fetching the file a second time")
    fo = _urllib.request.urlopen(url)
    data2 = fo.read()
    fo.close()

    if data1 == data2:
        print('  data are identical')
    else:
        print('  ERROR: DATA DIFFER')

    DEBUG = dbbackup


def test(url, N=10):
    print("checking error hander (do this on a non-200)")
    try: error_handler(url)
    except IOError as e:
        print("exiting - exception will prevent further tests")
        sys.exit()
    print()
    print("performing continuity test (making sure stuff isn't corrupted)")
    continuity(url)
    print()
    print("performing speed comparison")
    comp(N, url)
    print()
    print("performing dropped-connection check")
    test_timeout(url)

if __name__ == '__main__':
    import time
    import sys
    try:
        N = int(sys.argv[1])
        url = sys.argv[2]
    except:
        print("%s <integer> <url>" % sys.argv[0])
    else:
        test(url, N)
