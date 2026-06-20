"""
Minor modifications made by Miroslav Stampar (https://sqlmap.org)
for patching DNS-leakage occuring in socket.create_connection()

Minor modifications made by Christopher Gilbert (http://motomastyle.com/)
for use in PyLoris (http://pyloris.sourceforge.net/)

Minor modifications made by Mario Vilas (http://breakingcode.wordpress.com/)
mainly to merge bug fixes found in Sourceforge

"""

import functools
import socket
import struct

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultproxy = None
socket._orig_socket = _orgsocket = _orig_socket = socket.socket
_orgcreateconnection = socket.create_connection

class ProxyError(Exception): pass
class GeneralProxyError(ProxyError): pass
class Socks5AuthError(ProxyError): pass
class Socks5Error(ProxyError): pass
class Socks4Error(ProxyError): pass
class HTTPError(ProxyError): pass

_generalerrors = ("success",
    "invalid data",
    "not connected",
    "not available",
    "bad proxy type",
    "bad input")

_socks5errors = ("succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "Network unreachable",
    "Host unreachable",
    "Connection refused",
    "TTL expired",
    "Command not supported",
    "Address type not supported",
    "Unknown error")

_socks5autherrors = ("succeeded",
    "authentication is required",
    "all offered authentication methods were rejected",
    "unknown username or invalid password",
    "unknown error")

_socks4errors = ("request granted",
    "request rejected or failed",
    "request rejected because SOCKS server cannot connect to identd on the client",
    "request rejected because the client program and identd report different user-ids",
    "unknown error")

def setdefaultproxy(proxytype=None, addr=None, port=None, rdns=True, username=None, password=None):
    global _defaultproxy
    _defaultproxy = (proxytype, addr, port, rdns, username, password)

def wrapmodule(module):
    if _defaultproxy is not None:
        _orig_socket_ctor = _orgsocket

        @functools.wraps(_orig_socket_ctor)
        def guarded_socket(*args, **kwargs):
            family = args[0] if len(args) > 0 else kwargs.get("family", socket.AF_INET)
            stype  = args[1] if len(args) > 1 else kwargs.get("type", socket.SOCK_STREAM)

            flags = 0
            flags |= getattr(socket, "SOCK_CLOEXEC", 0)
            flags |= getattr(socket, "SOCK_NONBLOCK", 0)
            base_type = stype & ~flags

            if family in (socket.AF_INET, getattr(socket, "AF_INET6", socket.AF_INET)) and base_type == socket.SOCK_STREAM:
                return socksocket(*args, **kwargs)

            return _orig_socket_ctor(*args, **kwargs)

        module.socket.socket = guarded_socket

        if _defaultproxy[0] == PROXY_TYPE_SOCKS4:
            pass
        else:
            module.socket.create_connection = create_connection
    else:
        raise GeneralProxyError((4, "no proxy specified"))

def unwrapmodule(module):
    module.socket.socket = _orgsocket
    module.socket.create_connection = _orgcreateconnection

class socksocket(socket.socket):

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
        _orgsocket.__init__(self, family, type, proto, _sock)
        if _defaultproxy != None:
            self.__proxy = _defaultproxy
        else:
            self.__proxy = (None, None, None, None, None, None)
        self.__proxysockname = None
        self.__proxypeername = None

    def __recvall(self, count):
        data = self.recv(count)
        while len(data) < count:
            d = self.recv(count-len(data))
            if not d: raise GeneralProxyError((0, "connection closed unexpectedly"))
            data = data + d
        return data

    def setproxy(self, proxytype=None, addr=None, port=None, rdns=True, username=None, password=None):
        self.__proxy = (proxytype, addr, port, rdns, username, password)

    def __negotiatesocks5(self, destaddr, destport):
        if (self.__proxy[4]!=None) and (self.__proxy[5]!=None):
            self.sendall(struct.pack('BBBB', 0x05, 0x02, 0x00, 0x02))
        else:
            self.sendall(struct.pack('BBB', 0x05, 0x01, 0x00))
        chosenauth = self.__recvall(2)
        if chosenauth[0:1] != b'\x05':
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if chosenauth[1:2] == b'\x00':
            pass
        elif chosenauth[1:2] == b'\x02':
            self.sendall(b'\x01' + chr(len(self.__proxy[4])).encode() + self.__proxy[4].encode() + chr(len(self.__proxy[5])).encode() + self.__proxy[5].encode())
            authstat = self.__recvall(2)
            if authstat[0:1] != b'\x01':
                self.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1:2] != b'\x00':
                self.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
        else:
            self.close()
            if chosenauth[1:2] == b'\xff':
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        req = struct.pack('BBB', 0x05, 0x01, 0x00)
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + b'\x01' + ipaddr
        except socket.error:
            if self.__proxy[3]:
                ipaddr = None
                req = req + chr(0x03).encode() + chr(len(destaddr)).encode() + (destaddr if isinstance(destaddr, bytes) else destaddr.encode())
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + chr(0x01).encode() + ipaddr
        req = req + struct.pack(">H", destport)
        self.sendall(req)
        resp = self.__recvall(4)
        if resp[0:1] != chr(0x05).encode():
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1:2] != chr(0x00).encode():
            self.close()
            if ord(resp[1:2])<=8:
                raise Socks5Error((ord(resp[1:2]), _socks5errors[ord(resp[1:2])]))
            else:
                raise Socks5Error((9, _socks5errors[9]))
        elif resp[3:4] == chr(0x01).encode():
            boundaddr = self.__recvall(4)
        elif resp[3:4] == chr(0x03).encode():
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(ord(resp[4:5]))
        else:
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        boundport = struct.unpack(">H", self.__recvall(2))[0]
        self.__proxysockname = (boundaddr, boundport)
        if ipaddr != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def getproxysockname(self):
        return self.__proxysockname

    def getproxypeername(self):
        return _orgsocket.getpeername(self)

    def getpeername(self):
        return self.__proxypeername

    def __negotiatesocks4(self,destaddr,destport):
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            if self.__proxy[3]:
                ipaddr = struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01)
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        req = struct.pack(">BBH", 0x04, 0x01, destport) + ipaddr
        if self.__proxy[4] != None:
            req = req + self.__proxy[4]
        req = req + chr(0x00).encode()
        if rmtrslv:
            req = req + destaddr + chr(0x00).encode()
        self.sendall(req)
        resp = self.__recvall(8)
        if resp[0:1] != chr(0x00).encode():
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        if resp[1:2] != chr(0x5A).encode():
            self.close()
            if ord(resp[1:2]) in (91, 92, 93):
                self.close()
                raise Socks4Error((ord(resp[1:2]), _socks4errors[ord(resp[1:2]) - 90]))
            else:
                raise Socks4Error((94, _socks4errors[4]))
        self.__proxysockname = (socket.inet_ntoa(resp[4:]), struct.unpack(">H", resp[2:4])[0])
        if rmtrslv != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def __negotiatehttp(self, destaddr, destport):
        if not self.__proxy[3]:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        self.sendall(("CONNECT " + addr + ":" + str(destport) + " HTTP/1.1\r\n" + "Host: " + destaddr + "\r\n\r\n").encode())
        resp = self.recv(1)
        while resp.find("\r\n\r\n".encode()) == -1:
            resp = resp + self.recv(1)
        statusline = resp.splitlines()[0].split(" ".encode(), 2)
        if statusline[0] not in ("HTTP/1.0".encode(), "HTTP/1.1".encode()):
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode, statusline[2]))
        self.__proxysockname = ("0.0.0.0", 0)
        self.__proxypeername = (addr, destport)

    def connect(self, destpair):
        if (not type(destpair) in (list,tuple)) or (len(destpair) < 2) or (type(destpair[0]) != type('')) or (type(destpair[1]) != int):
            raise GeneralProxyError((5, _generalerrors[5]))
        if self.__proxy[0] == PROXY_TYPE_SOCKS5:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 1080
            _orgsocket.connect(self, (self.__proxy[1], portnum))
            self.__negotiatesocks5(destpair[0], destpair[1])
        elif self.__proxy[0] == PROXY_TYPE_SOCKS4:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 1080
            _orgsocket.connect(self,(self.__proxy[1], portnum))
            self.__negotiatesocks4(destpair[0], destpair[1])
        elif self.__proxy[0] == PROXY_TYPE_HTTP:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 8080
            _orgsocket.connect(self,(self.__proxy[1], portnum))
            self.__negotiatehttp(destpair[0], destpair[1])
        elif self.__proxy[0] == None:
            _orgsocket.connect(self, (destpair[0], destpair[1]))
        else:
            raise GeneralProxyError((4, _generalerrors[4]))

def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                    source_address=None):
    host, port = address
    sock = None
    try:
        sock = socksocket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(address)
    except socket.error:
        if sock is not None:
            sock.close()
        raise
    return sock
