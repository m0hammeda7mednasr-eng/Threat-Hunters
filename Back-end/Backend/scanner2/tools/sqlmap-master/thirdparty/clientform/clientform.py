__all__ = ['AmbiguityError', 'CheckboxControl', 'Control',
           'ControlNotFoundError', 'FileControl', 'FormParser', 'HTMLForm',
           'HiddenControl', 'IgnoreControl', 'ImageControl', 'IsindexControl',
           'Item', 'ItemCountError', 'ItemNotFoundError', 'Label',
           'ListControl', 'LocateError', 'Missing', 'ParseError', 'ParseFile',
           'ParseFileEx', 'ParseResponse', 'ParseResponseEx','PasswordControl',
           'RadioControl', 'ScalarControl', 'SelectControl',
           'SubmitButtonControl', 'SubmitControl', 'TextControl',
           'TextareaControl', 'XHTMLCompatibleFormParser']

try:
    import logging
    import inspect
except ImportError:
    def debug(msg, *args, **kwds):
        pass
else:
    _logger = logging.getLogger("ClientForm")
    OPTIMIZATION_HACK = True

    def debug(msg, *args, **kwds):
        if OPTIMIZATION_HACK:
            return

        caller_name = inspect.stack()[1][3]
        extended_msg = '%%s %s' % msg
        extended_args = (caller_name,)+args
        debug = _logger.debug(extended_msg, *extended_args, **kwds)

    def _show_debug_messages():
        global OPTIMIZATION_HACK
        OPTIMIZATION_HACK = False
        _logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        _logger.addHandler(handler)

try:
    from thirdparty import six
    from thirdparty.six import unichr as _unichr
    from thirdparty.six.moves import cStringIO as _cStringIO
    from thirdparty.six.moves import html_entities as _html_entities
    from thirdparty.six.moves import urllib as _urllib
except ImportError:
    import six
    from six import unichr as _unichr
    from six.moves import cStringIO as _cStringIO
    from six.moves import html_entities as _html_entities
    from six.moves import urllib as _urllib

try:
    import sgmllib
except ImportError:
    from lib.utils import sgmllib

import sys, re, random

if sys.version_info >= (3, 0):
    xrange = range

sgmllib.charref = re.compile("&#(x?[0-9a-fA-F]+)[^0-9a-fA-F]")

try:
    import HTMLParser
except ImportError:
    HAVE_MODULE_HTMLPARSER = False
else:
    HAVE_MODULE_HTMLPARSER = True

try:
    import warnings
except ImportError:
    def deprecation(message, stack_offset=0):
        pass
else:
    def deprecation(message, stack_offset=0):
        warnings.warn(message, DeprecationWarning, stacklevel=3+stack_offset)

VERSION = "0.2.10"

CHUNK = 1024  # size of chunks fed to parser, in bytes

DEFAULT_ENCODING = "latin-1"

class Missing: pass

_compress_re = re.compile(r"\s+")
def compress_text(text): return _compress_re.sub(" ", text.strip())

def normalize_line_endings(text):
    return re.sub(r"(?:(?<!\r)\n)|(?:\r(?!\n))", "\r\n", text)

def _quote_plus(value):
    if not isinstance(value, six.string_types):
        value = six.text_type(value)

    if isinstance(value, six.text_type):
        value = value.encode("utf8")

    return _urllib.parse.quote_plus(value)

def urlencode(query,doseq=False,):

    if hasattr(query,"items"):
        query = query.items()
    else:
        try:
            x = len(query)
            if len(query) and type(query[0]) != tuple:
                raise TypeError()
        except TypeError:
            ty,va,tb = sys.exc_info()
            raise TypeError("not a valid non-string sequence or mapping "
                            "object", tb)

    l = []
    if not doseq:
        for k, v in query:
            k = _quote_plus(k)
            v = _quote_plus(v)
            l.append(k + '=' + v)
    else:
        for k, v in query:
            k = _quote_plus(k)
            if isinstance(v, six.string_types):
                v = _quote_plus(v)
                l.append(k + '=' + v)
            else:
                try:
                    x = len(v)
                except TypeError:
                    v = _quote_plus(v)
                    l.append(k + '=' + v)
                else:
                    for elt in v:
                        l.append(k + '=' + _quote_plus(elt))
    return '&'.join(l)

def unescape(data, entities, encoding=DEFAULT_ENCODING):
    if data is None or "&" not in data:
        return data

    if isinstance(data, six.string_types):
        encoding = None

    def replace_entities(match, entities=entities, encoding=encoding):
        ent = match.group()
        if ent[1] == "#":
            return unescape_charref(ent[2:-1], encoding)

        repl = entities.get(ent)
        if repl is not None:
            if hasattr(repl, "decode") and encoding is not None:
                try:
                    repl = repl.decode(encoding)
                except UnicodeError:
                    repl = ent
        else:
            repl = ent

        return repl

    return re.sub(r"&#?[A-Za-z0-9]+?;", replace_entities, data)

def unescape_charref(data, encoding):
    name, base = data, 10
    if name.startswith("x"):
        name, base= name[1:], 16
    elif not name.isdigit():
        base = 16

    try:
        return _unichr(int(name, base))
    except:
        return data

def get_entitydefs():
    from codecs import latin_1_decode
    entitydefs = {}
    try:
        _html_entities.name2codepoint
    except AttributeError:
        entitydefs = {}
        for name, char in _html_entities.entitydefs.items():
            uc = latin_1_decode(char)[0]
            if uc.startswith("&#") and uc.endswith(";"):
                uc = unescape_charref(uc[2:-1], None)
            entitydefs["&%s;" % name] = uc
    else:
        for name, codepoint in _html_entities.name2codepoint.items():
            entitydefs["&%s;" % name] = _unichr(codepoint)
    return entitydefs

def issequence(x):
    try:
        x[0]
    except (TypeError, KeyError):
        return False
    except IndexError:
        pass
    return True

def isstringlike(x):
    try: x+""
    except: return False
    else: return True


def choose_boundary():
    nonce = "".join([str(random.randint(0, sys.maxsize-1)) for i in (0,1,2)])
    return "-"*27 + nonce

class MimeWriter:


    def __init__(self, fp, http_hdrs=None):
        self._http_hdrs = http_hdrs
        self._fp = fp
        self._headers = []
        self._boundary = []
        self._first_part = True

    def addheader(self, key, value, prefix=0,
                  add_to_http_hdrs=0):
        lines = value.split("\r\n")
        while lines and not lines[-1]: del lines[-1]
        while lines and not lines[0]: del lines[0]
        if add_to_http_hdrs:
            value = "".join(lines)
            self._http_hdrs.append((key.capitalize(), value))
        else:
            for i in xrange(1, len(lines)):
                lines[i] = "    " + lines[i].strip()
            value = "\r\n".join(lines) + "\r\n"
            line = key.title() + ": " + value
            if prefix:
                self._headers.insert(0, line)
            else:
                self._headers.append(line)

    def flushheaders(self):
        self._fp.writelines(self._headers)
        self._headers = []

    def startbody(self, ctype=None, plist=[], prefix=1,
                  add_to_http_hdrs=0, content_type=1):
        if content_type and ctype:
            for name, value in plist:
                ctype = ctype + ';\r\n %s=%s' % (name, value)
            self.addheader("Content-Type", ctype, prefix=prefix,
                           add_to_http_hdrs=add_to_http_hdrs)
        self.flushheaders()
        if not add_to_http_hdrs: self._fp.write("\r\n")
        self._first_part = True
        return self._fp

    def startmultipartbody(self, subtype, boundary=None, plist=[], prefix=1,
                           add_to_http_hdrs=0, content_type=1):
        boundary = boundary or choose_boundary()
        self._boundary.append(boundary)
        return self.startbody("multipart/" + subtype,
                              [("boundary", boundary)] + plist,
                              prefix=prefix,
                              add_to_http_hdrs=add_to_http_hdrs,
                              content_type=content_type)

    def nextpart(self):
        boundary = self._boundary[-1]
        if self._first_part:
            self._first_part = False
        else:
            self._fp.write("\r\n")
        self._fp.write("--" + boundary + "\r\n")
        return self.__class__(self._fp)

    def lastpart(self):
        if self._first_part:
            self.nextpart()
        boundary = self._boundary.pop()
        self._fp.write("\r\n--" + boundary + "--\r\n")


class LocateError(ValueError): pass
class AmbiguityError(LocateError): pass
class ControlNotFoundError(LocateError): pass
class ItemNotFoundError(LocateError): pass

class ItemCountError(ValueError): pass

if HAVE_MODULE_HTMLPARSER:
    SGMLLIB_PARSEERROR = sgmllib.SGMLParseError
    class ParseError(sgmllib.SGMLParseError,
                     HTMLParser.HTMLParseError,
                     ):
        pass
else:
    if hasattr(sgmllib, "SGMLParseError"):
        SGMLLIB_PARSEERROR = sgmllib.SGMLParseError
        class ParseError(sgmllib.SGMLParseError):
            pass
    else:
        SGMLLIB_PARSEERROR = RuntimeError
        class ParseError(RuntimeError):
            pass


class _AbstractFormParser:
    def __init__(self, entitydefs=None, encoding=DEFAULT_ENCODING):
        if entitydefs is None:
            entitydefs = get_entitydefs()
        self._entitydefs = entitydefs
        self._encoding = encoding

        self.base = None
        self.forms = []
        self.labels = []
        self._current_label = None
        self._current_form = None
        self._select = None
        self._optgroup = None
        self._option = None
        self._textarea = None

        self._global_form = None
        self.start_form([])
        self.end_form()
        self._current_form = self._global_form = self.forms[0]

    def do_base(self, attrs):
        debug("%s", attrs)
        for key, value in attrs:
            if key == "href":
                self.base = self.unescape_attr_if_required(value)

    def end_body(self):
        debug("")
        if self._current_label is not None:
            self.end_label()
        if self._current_form is not self._global_form:
            self.end_form()

    def start_form(self, attrs):
        debug("%s", attrs)
        if self._current_form is not self._global_form:
            raise ParseError("nested FORMs")
        name = None
        action = None
        enctype = "application/x-www-form-urlencoded"
        method = "GET"
        d = {}
        for key, value in attrs:
            if key == "name":
                name = self.unescape_attr_if_required(value)
            elif key == "action":
                action = self.unescape_attr_if_required(value)
            elif key == "method":
                method = self.unescape_attr_if_required(value.upper())
            elif key == "enctype":
                enctype = self.unescape_attr_if_required(value.lower())
            d[key] = self.unescape_attr_if_required(value)
        controls = []
        self._current_form = (name, action, method, enctype), d, controls

    def end_form(self):
        debug("")
        if self._current_label is not None:
            self.end_label()
        if self._current_form is self._global_form:
            raise ParseError("end of FORM before start")
        self.forms.append(self._current_form)
        self._current_form = self._global_form

    def start_select(self, attrs):
        debug("%s", attrs)
        if self._select is not None:
            raise ParseError("nested SELECTs")
        if self._textarea is not None:
            raise ParseError("SELECT inside TEXTAREA")
        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)

        self._select = d
        self._add_label(d)

        self._append_select_control({"__select": d})

    def end_select(self):
        debug("")
        if self._select is None:
            raise ParseError("end of SELECT before start")

        if self._option is not None:
            self._end_option()

        self._select = None

    def start_optgroup(self, attrs):
        debug("%s", attrs)
        if self._select is None:
            raise ParseError("OPTGROUP outside of SELECT")
        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)

        self._optgroup = d

    def end_optgroup(self):
        debug("")
        if self._optgroup is None:
            raise ParseError("end of OPTGROUP before start")
        self._optgroup = None

    def _start_option(self, attrs):
        debug("%s", attrs)
        if self._select is None:
            raise ParseError("OPTION outside of SELECT")
        if self._option is not None:
            self._end_option()

        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)

        self._option = {}
        self._option.update(d)
        if (self._optgroup and "disabled" in self._optgroup and
            "disabled" not in self._option):
            self._option["disabled"] = None

    def _end_option(self):
        debug("")
        if self._option is None:
            raise ParseError("end of OPTION before start")

        contents = self._option.get("contents", "").strip()
        self._option["contents"] = contents
        if "value" not in self._option:
            self._option["value"] = contents
        if "label" not in self._option:
            self._option["label"] = contents
        self._option["__select"] = self._select
        self._append_select_control(self._option)
        self._option = None

    def _append_select_control(self, attrs):
        debug("%s", attrs)
        controls = self._current_form[2]
        name = self._select.get("name")
        controls.append(("select", name, attrs))

    def start_textarea(self, attrs):
        debug("%s", attrs)
        if self._textarea is not None:
            raise ParseError("nested TEXTAREAs")
        if self._select is not None:
            raise ParseError("TEXTAREA inside SELECT")
        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)
        self._add_label(d)

        self._textarea = d

    def end_textarea(self):
        debug("")
        if self._textarea is None:
            raise ParseError("end of TEXTAREA before start")
        controls = self._current_form[2]
        name = self._textarea.get("name")
        controls.append(("textarea", name, self._textarea))
        self._textarea = None

    def start_label(self, attrs):
        debug("%s", attrs)
        if self._current_label:
            self.end_label()
        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)
        taken = bool(d.get("for"))  # empty id is invalid
        d["__text"] = ""
        d["__taken"] = taken
        if taken:
            self.labels.append(d)
        self._current_label = d

    def end_label(self):
        debug("")
        label = self._current_label
        if label is None:
            return
        self._current_label = None
        del label["__taken"]

    def _add_label(self, d):
        if self._current_label is not None:
            if not self._current_label["__taken"]:
                self._current_label["__taken"] = True
                d["__label"] = self._current_label

    def handle_data(self, data):
        debug("%s", data)

        if self._option is not None:
            map = self._option
            key = "contents"
        elif self._textarea is not None:
            map = self._textarea
            key = "value"
            data = normalize_line_endings(data)
        elif self._current_label is not None:
            map = self._current_label
            key = "__text"
        else:
            return

        if data and key not in map:
            if data[0:2] == "\r\n":
                data = data[2:]
            elif data[0:1] in ["\n", "\r"]:
                data = data[1:]
            map[key] = data
        else:
            map[key] = (map[key].decode("utf8", "replace") if isinstance(map[key], six.binary_type) else map[key]) + data

    def do_button(self, attrs):
        debug("%s", attrs)
        d = {}
        d["type"] = "submit"  # default
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)
        controls = self._current_form[2]

        type = d["type"]
        name = d.get("name")
        type = type+"button"
        self._add_label(d)
        controls.append((type, name, d))

    def do_input(self, attrs):
        debug("%s", attrs)
        d = {}
        d["type"] = "text"  # default
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)
        controls = self._current_form[2]

        type = d["type"]
        name = d.get("name")
        self._add_label(d)
        controls.append((type, name, d))

    def do_isindex(self, attrs):
        debug("%s", attrs)
        d = {}
        for key, val in attrs:
            d[key] = self.unescape_attr_if_required(val)
        controls = self._current_form[2]

        self._add_label(d)
        controls.append(("isindex", None, d))

    def handle_entityref(self, name):
        self.handle_data(unescape(
            '&%s;' % name, self._entitydefs, self._encoding))

    def handle_charref(self, name):
        self.handle_data(unescape_charref(name, self._encoding))

    def unescape_attr(self, name):
        return unescape(name, self._entitydefs, self._encoding)

    def unescape_attrs(self, attrs):
        escaped_attrs = {}
        for key, val in attrs.items():
            try:
                val.items
            except AttributeError:
                escaped_attrs[key] = self.unescape_attr(val)
            else:
                escaped_attrs[key] = self.unescape_attrs(val)
        return escaped_attrs

    def unknown_entityref(self, ref): self.handle_data("&%s;" % ref)
    def unknown_charref(self, ref): self.handle_data("&#%s;" % ref)


if not HAVE_MODULE_HTMLPARSER:
    class XHTMLCompatibleFormParser:
        def __init__(self, entitydefs=None, encoding=DEFAULT_ENCODING):
            raise ValueError("HTMLParser could not be imported")
else:
    class XHTMLCompatibleFormParser(_AbstractFormParser, HTMLParser.HTMLParser):
        def __init__(self, entitydefs=None, encoding=DEFAULT_ENCODING):
            HTMLParser.HTMLParser.__init__(self)
            _AbstractFormParser.__init__(self, entitydefs, encoding)

        def feed(self, data):
            try:
                HTMLParser.HTMLParser.feed(self, data)
            except HTMLParser.HTMLParseError as exc:
                raise ParseError(exc)

        def start_option(self, attrs):
            _AbstractFormParser._start_option(self, attrs)

        def end_option(self):
            _AbstractFormParser._end_option(self)

        def handle_starttag(self, tag, attrs):
            try:
                method = getattr(self, "start_" + tag)
            except AttributeError:
                try:
                    method = getattr(self, "do_" + tag)
                except AttributeError:
                    pass  # unknown tag
                else:
                    method(attrs)
            else:
                method(attrs)

        def handle_endtag(self, tag):
            try:
                method = getattr(self, "end_" + tag)
            except AttributeError:
                pass  # unknown tag
            else:
                method()

        def unescape(self, name):
            return self.unescape_attr(name)

        def unescape_attr_if_required(self, name):
            return name  # HTMLParser.HTMLParser already did it
        def unescape_attrs_if_required(self, attrs):
            return attrs  # ditto

        def close(self):
            HTMLParser.HTMLParser.close(self)
            self.end_body()


class _AbstractSgmllibParser(_AbstractFormParser):

    def do_option(self, attrs):
        _AbstractFormParser._start_option(self, attrs)

    if sys.version_info[:2] >= (2,5):
        entity_or_charref = re.compile(
            '&(?:([a-zA-Z][-.a-zA-Z0-9]*)|#(x?[0-9a-fA-F]+))(;?)')
        def convert_entityref(self, name):
            return unescape("&%s;" % name, self._entitydefs, self._encoding)
        def convert_charref(self, name):
            return unescape_charref("%s" % name, self._encoding)
        def unescape_attr_if_required(self, name):
            return name  # sgmllib already did it
        def unescape_attrs_if_required(self, attrs):
            return attrs  # ditto
    else:
        def unescape_attr_if_required(self, name):
            return self.unescape_attr(name)
        def unescape_attrs_if_required(self, attrs):
            return self.unescape_attrs(attrs)


class FormParser(_AbstractSgmllibParser, sgmllib.SGMLParser):
    def __init__(self, entitydefs=None, encoding=DEFAULT_ENCODING):
        sgmllib.SGMLParser.__init__(self)
        _AbstractFormParser.__init__(self, entitydefs, encoding)

    def feed(self, data):
        try:
            sgmllib.SGMLParser.feed(self, data)
        except SGMLLIB_PARSEERROR as exc:
            raise ParseError(exc)

    def close(self):
        sgmllib.SGMLParser.close(self)
        self.end_body()



def _create_bs_classes(bs,
                       icbinbs,
                       ):
    class _AbstractBSFormParser(_AbstractSgmllibParser):
        bs_base_class = None
        def __init__(self, entitydefs=None, encoding=DEFAULT_ENCODING):
            _AbstractFormParser.__init__(self, entitydefs, encoding)
            self.bs_base_class.__init__(self)
        def handle_data(self, data):
            _AbstractFormParser.handle_data(self, data)
            self.bs_base_class.handle_data(self, data)
        def feed(self, data):
            try:
                self.bs_base_class.feed(self, data)
            except SGMLLIB_PARSEERROR as exc:
                raise ParseError(exc)
        def close(self):
            self.bs_base_class.close(self)
            self.end_body()

    class RobustFormParser(_AbstractBSFormParser, bs):
        pass
    RobustFormParser.bs_base_class = bs
    class NestingRobustFormParser(_AbstractBSFormParser, icbinbs):
        pass
    NestingRobustFormParser.bs_base_class = icbinbs

    return RobustFormParser, NestingRobustFormParser

try:
    if sys.version_info[:2] < (2, 2):
        raise ImportError  # BeautifulSoup uses generators
    import BeautifulSoup
except ImportError:
    pass
else:
    RobustFormParser, NestingRobustFormParser = _create_bs_classes(
        BeautifulSoup.BeautifulSoup, BeautifulSoup.ICantBelieveItsBeautifulSoup
        )
    __all__ += ['RobustFormParser', 'NestingRobustFormParser']




def ParseResponseEx(response,
                    select_default=False,
                    form_parser_class=FormParser,
                    request_class=_urllib.request.Request,
                    entitydefs=None,
                    encoding=DEFAULT_ENCODING,

                    _urljoin=_urllib.parse.urljoin,
                    _urlparse=_urllib.parse.urlparse,
                    _urlunparse=_urllib.parse.urlunparse,
                    ):
    return _ParseFileEx(response, response.geturl(),
                        select_default,
                        False,
                        form_parser_class,
                        request_class,
                        entitydefs,
                        False,
                        encoding,
                        _urljoin=_urljoin,
                        _urlparse=_urlparse,
                        _urlunparse=_urlunparse,
                        )

def ParseFileEx(file, base_uri,
                select_default=False,
                form_parser_class=FormParser,
                request_class=_urllib.request.Request,
                entitydefs=None,
                encoding=DEFAULT_ENCODING,

                _urljoin=_urllib.parse.urljoin,
                _urlparse=_urllib.parse.urlparse,
                _urlunparse=_urllib.parse.urlunparse,
                ):
    return _ParseFileEx(file, base_uri,
                        select_default,
                        False,
                        form_parser_class,
                        request_class,
                        entitydefs,
                        False,
                        encoding,
                        _urljoin=_urljoin,
                        _urlparse=_urlparse,
                        _urlunparse=_urlunparse,
                        )

def ParseResponse(response, *args, **kwds):
    return _ParseFileEx(response, response.geturl(), *args, **kwds)[1:]

def ParseFile(file, base_uri, *args, **kwds):
    return _ParseFileEx(file, base_uri, *args, **kwds)[1:]

def _ParseFileEx(file, base_uri,
                 select_default=False,
                 ignore_errors=False,
                 form_parser_class=FormParser,
                 request_class=_urllib.request.Request,
                 entitydefs=None,
                 backwards_compat=True,
                 encoding=DEFAULT_ENCODING,
                 _urljoin=_urllib.parse.urljoin,
                 _urlparse=_urllib.parse.urlparse,
                 _urlunparse=_urllib.parse.urlunparse,
                 ):
    if backwards_compat:
        deprecation("operating in backwards-compatibility mode", 1)
    fp = form_parser_class(entitydefs, encoding)
    while 1:
        data = file.read(CHUNK)
        try:
            fp.feed(data)
        except ParseError as e:
            e.base_uri = base_uri
            raise
        if len(data) != CHUNK: break
    fp.close()
    if fp.base is not None:
        base_uri = fp.base
    labels = []  # Label(label) for label in fp.labels]
    id_to_labels = {}
    for l in fp.labels:
        label = Label(l)
        labels.append(label)
        for_id = l["for"]
        coll = id_to_labels.get(for_id)
        if coll is None:
            id_to_labels[for_id] = [label]
        else:
            coll.append(label)
    forms = []
    for (name, action, method, enctype), attrs, controls in fp.forms:
        if action is None:
            action = base_uri
        else:
            action = six.text_type(action, "utf8") if action and isinstance(action, six.binary_type) else action
            action = _urljoin(base_uri, action)
        form = HTMLForm(
            action, method, enctype, name, attrs, request_class,
            forms, labels, id_to_labels, backwards_compat)
        form._urlparse = _urlparse
        form._urlunparse = _urlunparse
        for ii in xrange(len(controls)):
            type, name, attrs = controls[ii]
            form.new_control(
                type, name, attrs, select_default=select_default, index=ii*10)
        forms.append(form)
    for form in forms:
        try:
            form.fixup()
        except AttributeError as ex:
            if not any(_ in str(ex) for _ in ("is disabled", "is readonly")):
                raise
    return forms


class Label:
    def __init__(self, attrs):
        self.id = attrs.get("for")
        self._text = attrs.get("__text").strip()
        self._ctext = compress_text(self._text)
        self.attrs = attrs
        self._backwards_compat = False  # maintained by HTMLForm

    def __getattr__(self, name):
        if name == "text":
            if self._backwards_compat:
                return self._text
            else:
                return self._ctext
        return getattr(Label, name)

    def __setattr__(self, name, value):
        if name == "text":
            raise AttributeError("text attribute is read-only")
        self.__dict__[name] = value

    def __str__(self):
        return "<Label(id=%r, text=%r)>" % (self.id, self.text)


def _get_label(attrs):
    text = attrs.get("__label")
    if text is not None:
        return Label(text)
    else:
        return None

class Control:
    def __init__(self, type, name, attrs, index=None):
        raise NotImplementedError()

    def add_to_form(self, form):
        self._form = form
        form.controls.append(self)

    def fixup(self):
        pass

    def is_of_kind(self, kind):
        raise NotImplementedError()

    def clear(self):
        raise NotImplementedError()

    def __getattr__(self, name): raise NotImplementedError()
    def __setattr__(self, name, value): raise NotImplementedError()

    def pairs(self):
        return [(k, v) for (i, k, v) in self._totally_ordered_pairs()]

    def _totally_ordered_pairs(self):
        raise NotImplementedError()

    def _write_mime_data(self, mw, name, value):
        mw2 = mw.nextpart()
        mw2.addheader("Content-Disposition",
                      'form-data; name="%s"' % name, 1)
        f = mw2.startbody(prefix=0)
        f.write(value)

    def __str__(self):
        raise NotImplementedError()

    def get_labels(self):
        res = []
        if self._label:
            res.append(self._label)
        if self.id:
            res.extend(self._form._id_to_labels.get(self.id, ()))
        return res


class ScalarControl(Control):
    def __init__(self, type, name, attrs, index=None):
        self._index = index
        self._label = _get_label(attrs)
        self.__dict__["type"] = type.lower()
        self.__dict__["name"] = name
        self._value = attrs.get("value")
        self.disabled = "disabled" in attrs
        self.readonly = "readonly" in attrs
        self.id = attrs.get("id")

        self.attrs = attrs.copy()

        self._clicked = False

        self._urlparse = _urllib.parse.urlparse
        self._urlunparse = _urllib.parse.urlunparse

    def __getattr__(self, name):
        if name == "value":
            return self.__dict__["_value"]
        else:
            raise AttributeError("%s instance has no attribute '%s'" %
                                 (self.__class__.__name__, name))

    def __setattr__(self, name, value):
        if name == "value":
            if not isstringlike(value):
                raise TypeError("must assign a string")
            elif self.readonly:
                raise AttributeError("control '%s' is readonly" % self.name)
            elif self.disabled:
                raise AttributeError("control '%s' is disabled" % self.name)
            self.__dict__["_value"] = value
        elif name in ("name", "type"):
            raise AttributeError("%s attribute is readonly" % name)
        else:
            self.__dict__[name] = value

    def _totally_ordered_pairs(self):
        name = self.name
        value = self.value
        if name is None or value is None or self.disabled:
            return []
        return [(self._index, name, value)]

    def clear(self):
        if self.readonly:
            raise AttributeError("control '%s' is readonly" % self.name)
        self.__dict__["_value"] = None

    def __str__(self):
        name = self.name
        value = self.value
        if name is None: name = "<None>"
        if value is None: value = "<None>"

        infos = []
        if self.disabled: infos.append("disabled")
        if self.readonly: infos.append("readonly")
        info = ", ".join(infos)
        if info: info = " (%s)" % info

        return "<%s(%s=%s)%s>" % (self.__class__.__name__, name, value, info)


class TextControl(ScalarControl):
    def __init__(self, type, name, attrs, index=None):
        ScalarControl.__init__(self, type, name, attrs, index)
        if self.type == "hidden": self.readonly = True
        if self._value is None:
            self._value = ""

    def is_of_kind(self, kind): return kind == "text"

class FileControl(ScalarControl):

    def __init__(self, type, name, attrs, index=None):
        ScalarControl.__init__(self, type, name, attrs, index)
        self._value = None
        self._upload_data = []

    def is_of_kind(self, kind): return kind == "file"

    def clear(self):
        if self.readonly:
            raise AttributeError("control '%s' is readonly" % self.name)
        self._upload_data = []

    def __setattr__(self, name, value):
        if name in ("value", "name", "type"):
            raise AttributeError("%s attribute is readonly" % name)
        else:
            self.__dict__[name] = value

    def add_file(self, file_object, content_type=None, filename=None):
        if not hasattr(file_object, "read"):
            raise TypeError("file-like object must have read method")
        if content_type is not None and not isstringlike(content_type):
            raise TypeError("content type must be None or string-like")
        if filename is not None and not isstringlike(filename):
            raise TypeError("filename must be None or string-like")
        if content_type is None:
            content_type = "application/octet-stream"
        self._upload_data.append((file_object, content_type, filename))

    def _totally_ordered_pairs(self):
        if self.name is None or self.disabled:
            return []
        return [(self._index, self.name, "")]

    def _write_mime_data(self, mw, _name, _value):
        if len(self._upload_data) < 2:
            if len(self._upload_data) == 0:
                file_object = _cStringIO()
                content_type = "application/octet-stream"
                filename = ""
            else:
                file_object, content_type, filename = self._upload_data[0]
                if filename is None:
                    filename = ""
            mw2 = mw.nextpart()
            fn_part = '; filename="%s"' % filename
            disp = 'form-data; name="%s"%s' % (self.name, fn_part)
            mw2.addheader("Content-Disposition", disp, prefix=1)
            fh = mw2.startbody(content_type, prefix=0)
            fh.write(file_object.read())
        else:
            mw2 = mw.nextpart()
            disp = 'form-data; name="%s"' % self.name
            mw2.addheader("Content-Disposition", disp, prefix=1)
            fh = mw2.startmultipartbody("mixed", prefix=0)
            for file_object, content_type, filename in self._upload_data:
                mw3 = mw2.nextpart()
                if filename is None:
                    filename = ""
                fn_part = '; filename="%s"' % filename
                disp = "file%s" % fn_part
                mw3.addheader("Content-Disposition", disp, prefix=1)
                fh2 = mw3.startbody(content_type, prefix=0)
                fh2.write(file_object.read())
            mw2.lastpart()

    def __str__(self):
        name = self.name
        if name is None: name = "<None>"

        if not self._upload_data:
            value = "<No files added>"
        else:
            value = []
            for file, ctype, filename in self._upload_data:
                if filename is None:
                    value.append("<Unnamed file>")
                else:
                    value.append(filename)
            value = ", ".join(value)

        info = []
        if self.disabled: info.append("disabled")
        if self.readonly: info.append("readonly")
        info = ", ".join(info)
        if info: info = " (%s)" % info

        return "<%s(%s=%s)%s>" % (self.__class__.__name__, name, value, info)


class IsindexControl(ScalarControl):
    def __init__(self, type, name, attrs, index=None):
        ScalarControl.__init__(self, type, name, attrs, index)
        if self._value is None:
            self._value = ""

    def is_of_kind(self, kind): return kind in ["text", "clickable"]

    def _totally_ordered_pairs(self):
        return []

    def _click(self, form, coord, return_type, request_class=_urllib.request.Request):
        parts = self._urlparse(form.action)
        rest, (query, frag) = parts[:-2], parts[-2:]
        parts = rest + (_urllib.parse.quote_plus(self.value), None)
        url = self._urlunparse(parts)
        req_data = url, None, []

        if return_type == "pairs":
            return []
        elif return_type == "request_data":
            return req_data
        else:
            return request_class(url)

    def __str__(self):
        value = self.value
        if value is None: value = "<None>"

        infos = []
        if self.disabled: infos.append("disabled")
        if self.readonly: infos.append("readonly")
        info = ", ".join(infos)
        if info: info = " (%s)" % info

        return "<%s(%s)%s>" % (self.__class__.__name__, value, info)


class IgnoreControl(ScalarControl):
    def __init__(self, type, name, attrs, index=None):
        ScalarControl.__init__(self, type, name, attrs, index)
        self._value = None

    def is_of_kind(self, kind): return False

    def __setattr__(self, name, value):
        if name == "value":
            raise AttributeError(
                "control '%s' is ignored, hence read-only" % self.name)
        elif name in ("name", "type"):
            raise AttributeError("%s attribute is readonly" % name)
        else:
            self.__dict__[name] = value




class Item:
    def __init__(self, control, attrs, index=None):
        label = _get_label(attrs)
        self.__dict__.update({
            "name": attrs["value"],
            "_labels": label and [label] or [],
            "attrs": attrs,
            "_control": control,
            "disabled": "disabled" in attrs,
            "_selected": False,
            "id": attrs.get("id"),
            "_index": index,
            })
        control.items.append(self)

    def get_labels(self):
        res = []
        res.extend(self._labels)
        if self.id:
            res.extend(self._control._form._id_to_labels.get(self.id, ()))
        return res

    def __getattr__(self, name):
        if name=="selected":
            return self._selected
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name == "selected":
            self._control._set_selected_state(self, value)
        elif name == "disabled":
            self.__dict__["disabled"] = bool(value)
        else:
            raise AttributeError(name)

    def __str__(self):
        res = self.name
        if self.selected:
            res = "*" + res
        if self.disabled:
            res = "(%s)" % res
        return res

    def __repr__(self):
        attrs = [("name", self.name), ("id", self.id)]+self.attrs.items()
        return "<%s %s>" % (
            self.__class__.__name__,
            " ".join(["%s=%r" % (k, v) for k, v in attrs])
            )

def disambiguate(items, nr, **kwds):
    msgs = []
    for key, value in kwds.items():
        msgs.append("%s=%r" % (key, value))
    msg = " ".join(msgs)
    if not items:
        raise ItemNotFoundError(msg)
    if nr is None:
        if len(items) > 1:
            raise AmbiguityError(msg)
        nr = 0
    if len(items) <= nr:
        raise ItemNotFoundError(msg)
    return items[nr]

class ListControl(Control):






    _label = None

    def __init__(self, type, name, attrs={}, select_default=False,
                 called_as_base_class=False, index=None):
        if not called_as_base_class:
            raise NotImplementedError()

        self.__dict__["type"] = type.lower()
        self.__dict__["name"] = name
        self._value = attrs.get("value")
        self.disabled = False
        self.readonly = False
        self.id = attrs.get("id")
        self._closed = False

        self.items = []
        self._form = None

        self._select_default = select_default
        self._clicked = False

    def clear(self):
        self.value = []

    def is_of_kind(self, kind):
        if kind  == "list":
            return True
        elif kind == "multilist":
            return bool(self.multiple)
        elif kind == "singlelist":
            return not self.multiple
        else:
            return False

    def get_items(self, name=None, label=None, id=None,
                  exclude_disabled=False):
        if name is not None and not isstringlike(name):
            raise TypeError("item name must be string-like")
        if label is not None and not isstringlike(label):
            raise TypeError("item label must be string-like")
        if id is not None and not isstringlike(id):
            raise TypeError("item id must be string-like")
        items = []  # order is important
        compat = self._form.backwards_compat
        for o in self.items:
            if exclude_disabled and o.disabled:
                continue
            if name is not None and o.name != name:
                continue
            if label is not None:
                for l in o.get_labels():
                    if ((compat and l.text == label) or
                        (not compat and l.text.find(label) > -1)):
                        break
                else:
                    continue
            if id is not None and o.id != id:
                continue
            items.append(o)
        return items

    def get(self, name=None, label=None, id=None, nr=None,
            exclude_disabled=False):
        if nr is None and self._form.backwards_compat:
            nr = 0  # :-/
        items = self.get_items(name, label, id, exclude_disabled)
        return disambiguate(items, nr, name=name, label=label, id=id)

    def _get(self, name, by_label=False, nr=None, exclude_disabled=False):
        if by_label:
            name, label = None, name
        else:
            name, label = name, None
        return self.get(name, label, nr, exclude_disabled)

    def toggle(self, name, by_label=False, nr=None):
        deprecation(
            "item = control.get(...); item.selected = not item.selected")
        o = self._get(name, by_label, nr)
        self._set_selected_state(o, not o.selected)

    def set(self, selected, name, by_label=False, nr=None):
        deprecation(
            "control.get(...).selected = <boolean>")
        self._set_selected_state(self._get(name, by_label, nr), selected)

    def _set_selected_state(self, item, action):
        if self.disabled:
            raise AttributeError("control '%s' is disabled" % self.name)
        if self.readonly:
            raise AttributeError("control '%s' is readonly" % self.name)
        action = bool(action)
        compat = self._form.backwards_compat
        if not compat and item.disabled:
            raise AttributeError("item is disabled")
        else:
            if compat and item.disabled and action:
                raise AttributeError("item is disabled")
            if self.multiple:
                item.__dict__["_selected"] = action
            else:
                if not action:
                    item.__dict__["_selected"] = False
                else:
                    for o in self.items:
                        o.__dict__["_selected"] = False
                    item.__dict__["_selected"] = True

    def toggle_single(self, by_label=None):
        deprecation(
            "control.items[0].selected = not control.items[0].selected")
        if len(self.items) != 1:
            raise ItemCountError(
                "'%s' is not a single-item control" % self.name)
        item = self.items[0]
        self._set_selected_state(item, not item.selected)

    def set_single(self, selected, by_label=None):
        deprecation(
            "control.items[0].selected = <boolean>")
        if len(self.items) != 1:
            raise ItemCountError(
                "'%s' is not a single-item control" % self.name)
        self._set_selected_state(self.items[0], selected)

    def get_item_disabled(self, name, by_label=False, nr=None):
        deprecation(
            "control.get(...).disabled")
        return self._get(name, by_label, nr).disabled

    def set_item_disabled(self, disabled, name, by_label=False, nr=None):
        deprecation(
            "control.get(...).disabled = <boolean>")
        self._get(name, by_label, nr).disabled = disabled

    def set_all_items_disabled(self, disabled):
        for o in self.items:
            o.disabled = disabled

    def get_item_attrs(self, name, by_label=False, nr=None):
        deprecation(
            "control.get(...).attrs")
        return self._get(name, by_label, nr).attrs

    def close_control(self):
        self._closed = True

    def add_to_form(self, form):
        assert self._form is None or form == self._form, (
            "can't add control to more than one form")
        self._form = form
        if self.name is None:
            Control.add_to_form(self, form)
        else:
            for ii in xrange(len(form.controls)-1, -1, -1):
                control = form.controls[ii]
                if control.name == self.name and control.type == self.type:
                    if control._closed:
                        Control.add_to_form(self, form)
                    else:
                        control.merge_control(self)
                    break
            else:
                Control.add_to_form(self, form)

    def merge_control(self, control):
        assert bool(control.multiple) == bool(self.multiple)
        self.items.extend(control.items)

    def fixup(self):



        for o in self.items: 
            o.__dict__["_control"] = self

    def __getattr__(self, name):
        if name == "value":
            compat = self._form.backwards_compat
            if self.name is None:
                return []
            return [o.name for o in self.items if o.selected and
                    (not o.disabled or compat)]
        else:
            raise AttributeError("%s instance has no attribute '%s'" %
                                 (self.__class__.__name__, name))

    def __setattr__(self, name, value):
        if name == "value":
            if self.disabled:
                raise AttributeError("control '%s' is disabled" % self.name)
            if self.readonly:
                raise AttributeError("control '%s' is readonly" % self.name)
            self._set_value(value)
        elif name in ("name", "type", "multiple"):
            raise AttributeError("%s attribute is readonly" % name)
        else:
            self.__dict__[name] = value

    def _set_value(self, value):
        if value is None or isstringlike(value):
            raise TypeError("ListControl, must set a sequence")
        if not value:
            compat = self._form.backwards_compat
            for o in self.items:
                if not o.disabled or compat:
                    o.selected = False
        elif self.multiple:
            self._multiple_set_value(value)
        elif len(value) > 1:
            raise ItemCountError(
                "single selection list, must set sequence of "
                "length 0 or 1")
        else:
            self._single_set_value(value)

    def _get_items(self, name, target=1):
        all_items = self.get_items(name)
        items = [o for o in all_items if not o.disabled]
        if len(items) < target:
            if len(all_items) < target:
                raise ItemNotFoundError(
                    "insufficient items with name %r" % name)
            else:
                raise AttributeError(
                    "insufficient non-disabled items with name %s" % name)
        on = []
        off = []
        for o in items:
            if o.selected:
                on.append(o)
            else:
                off.append(o)
        return on, off

    def _single_set_value(self, value):
        assert len(value) == 1
        on, off = self._get_items(value[0])
        assert len(on) <= 1
        if not on:
            off[0].selected = True

    def _multiple_set_value(self, value):
        compat = self._form.backwards_compat
        turn_on = []  # transactional-ish
        turn_off = [item for item in self.items if
                    item.selected and (not item.disabled or compat)]
        names = {}
        for nn in value:
            if nn in names.keys():
                names[nn] += 1
            else:
                names[nn] = 1
        for name, count in names.items():
            on, off = self._get_items(name, count)
            for i in xrange(count):
                if on:
                    item = on[0]
                    del on[0]
                    del turn_off[turn_off.index(item)]
                else:
                    item = off[0]
                    del off[0]
                    turn_on.append(item)
        for item in turn_off:
            item.selected = False
        for item in turn_on:
            item.selected = True

    def set_value_by_label(self, value):
        if isstringlike(value):
            raise TypeError(value)
        if not self.multiple and len(value) > 1:
            raise ItemCountError(
                "single selection list, must set sequence of "
                "length 0 or 1")
        items = []
        for nn in value:
            found = self.get_items(label=nn)
            if len(found) > 1:
                if not self._form.backwards_compat:
                    opt_name = found[0].name
                    if [o for o in found[1:] if o.name != opt_name]:
                        raise AmbiguityError(nn)
                else:
                    found = found[:1]
            for o in found:
                if self._form.backwards_compat or o not in items:
                    items.append(o)
                    break
            else:  # all of them are used
                raise ItemNotFoundError(nn)
        self.value = []
        for o in items:
            o.selected = True

    def get_value_by_label(self):
        res = []
        compat = self._form.backwards_compat
        for o in self.items:
            if (not o.disabled or compat) and o.selected:
                for l in o.get_labels():
                    if l.text:
                        res.append(l.text)
                        break
                else:
                    res.append(None)
        return res

    def possible_items(self, by_label=False):
        deprecation(
            "[item.name for item in self.items]")
        if by_label:
            res = []
            for o in self.items:
                for l in o.get_labels():
                    if l.text:
                        res.append(l.text)
                        break
                else:
                    res.append(None)
            return res
        return [o.name for o in self.items]

    def _totally_ordered_pairs(self):
        if self.disabled or self.name is None:
            return []
        else:
            return [(o._index, self.name, o.name) for o in self.items
                    if o.selected and not o.disabled]

    def __str__(self):
        name = self.name
        if name is None: name = "<None>"

        display = [str(o) for o in self.items]

        infos = []
        if self.disabled: infos.append("disabled")
        if self.readonly: infos.append("readonly")
        info = ", ".join(infos)
        if info: info = " (%s)" % info

        return "<%s(%s=[%s])%s>" % (self.__class__.__name__,
                                    name, ", ".join(display), info)


class RadioControl(ListControl):
    def __init__(self, type, name, attrs, select_default=False, index=None):
        attrs.setdefault("value", "on")
        ListControl.__init__(self, type, name, attrs, select_default,
                             called_as_base_class=True, index=index)
        self.__dict__["multiple"] = False
        o = Item(self, attrs, index)
        o.__dict__["_selected"] = "checked" in attrs

    def fixup(self):
        ListControl.fixup(self)
        found = [o for o in self.items if o.selected and not o.disabled]
        if not found:
            if self._select_default:
                for o in self.items:
                    if not o.disabled:
                        o.selected = True
                        break
        else:
            for o in found[:-1]:
                o.selected = False

    def get_labels(self):
        return []

class CheckboxControl(ListControl):
    def __init__(self, type, name, attrs, select_default=False, index=None):
        attrs.setdefault("value", "on")
        ListControl.__init__(self, type, name, attrs, select_default,
                             called_as_base_class=True, index=index)
        self.__dict__["multiple"] = True
        o = Item(self, attrs, index)
        o.__dict__["_selected"] = "checked" in attrs

    def get_labels(self):
        return []


class SelectControl(ListControl):

    def __init__(self, type, name, attrs, select_default=False, index=None):
        self.attrs = attrs["__select"].copy()
        self.__dict__["_label"] = _get_label(self.attrs)
        self.__dict__["id"] = self.attrs.get("id")
        self.__dict__["multiple"] = "multiple" in self.attrs
        contents = attrs.get("contents")
        attrs = attrs.copy()
        del attrs["__select"]

        ListControl.__init__(self, type, name, self.attrs, select_default,
                             called_as_base_class=True, index=index)
        self.disabled = "disabled" in self.attrs
        self.readonly = "readonly" in self.attrs
        if "value" in attrs:
            o = Item(self, attrs, index)
            o.__dict__["_selected"] = "selected" in attrs
            label = attrs.get("label")
            if label:
                o._labels.append(Label({"__text": label}))
                if contents and contents != label:
                    o._labels.append(Label({"__text": contents}))
            elif contents:
                o._labels.append(Label({"__text": contents}))

    def fixup(self):
        ListControl.fixup(self)
        found = [o for o in self.items if o.selected]
        if not found:
            if not self.multiple or self._select_default:
                for o in self.items:
                    if not o.disabled:
                        was_disabled = self.disabled
                        self.disabled = False
                        try:
                            o.selected = True
                        finally:
                            o.disabled = was_disabled
                        break
        elif not self.multiple:
            for o in found[:-1]:
                o.selected = False


class SubmitControl(ScalarControl):
    def __init__(self, type, name, attrs, index=None):
        ScalarControl.__init__(self, type, name, attrs, index)
        if self.value is None and not self.disabled and not self.readonly: self.value = ""
        self.readonly = True

    def get_labels(self):
        res = []
        if self.value:
            res.append(Label({"__text": self.value}))
        res.extend(ScalarControl.get_labels(self))
        return res

    def is_of_kind(self, kind): return kind == "clickable"

    def _click(self, form, coord, return_type, request_class=_urllib.request.Request):
        self._clicked = coord
        r = form._switch_click(return_type, request_class)
        self._clicked = False
        return r

    def _totally_ordered_pairs(self):
        if not self._clicked:
            return []
        return ScalarControl._totally_ordered_pairs(self)


class ImageControl(SubmitControl):
    def __init__(self, type, name, attrs, index=None):
        SubmitControl.__init__(self, type, name, attrs, index)
        self.readonly = False

    def _totally_ordered_pairs(self):
        clicked = self._clicked
        if self.disabled or not clicked:
            return []
        name = self.name
        if name is None: return []
        pairs = [
            (self._index, "%s.x" % name, str(clicked[0])),
            (self._index+1, "%s.y" % name, str(clicked[1])),
            ]
        value = self._value
        if value:
            pairs.append((self._index+2, name, value))
        return pairs

    get_labels = ScalarControl.get_labels

class PasswordControl(TextControl): pass
class HiddenControl(TextControl): pass
class TextareaControl(TextControl): pass
class SubmitButtonControl(SubmitControl): pass


def is_listcontrol(control): return control.is_of_kind("list")


class HTMLForm:

    type2class = {
        "text": TextControl,
        "password": PasswordControl,
        "hidden": HiddenControl,
        "textarea": TextareaControl,

        "isindex": IsindexControl,

        "file": FileControl,

        "button": IgnoreControl,
        "buttonbutton": IgnoreControl,
        "reset": IgnoreControl,
        "resetbutton": IgnoreControl,

        "submit": SubmitControl,
        "submitbutton": SubmitButtonControl,
        "image": ImageControl,

        "radio": RadioControl,
        "checkbox": CheckboxControl,
        "select": SelectControl,
        }


    def __init__(self, action, method="GET",
                 enctype=None,
                 name=None, attrs=None,
                 request_class=_urllib.request.Request,
                 forms=None, labels=None, id_to_labels=None,
                 backwards_compat=True):
        self.action = action
        self.method = method
        self.enctype = enctype or "application/x-www-form-urlencoded"
        self.name = name
        if attrs is not None:
            self.attrs = attrs.copy()
        else:
            self.attrs = {}
        self.controls = []
        self._request_class = request_class

        self._forms = forms  # this is a semi-public API!
        self._labels = labels  # this is a semi-public API!
        self._id_to_labels = id_to_labels  # this is a semi-public API!

        self.backwards_compat = backwards_compat  # note __setattr__

        self._urlunparse = _urllib.parse.urlunparse
        self._urlparse = _urllib.parse.urlparse

    def __getattr__(self, name):
        if name == "backwards_compat":
            return self._backwards_compat
        return getattr(HTMLForm, name)

    def __setattr__(self, name, value):
        if name == "backwards_compat":
            name = "_backwards_compat"
            value = bool(value)
            for cc in self.controls:
                try:
                    items = cc.items 
                except AttributeError:
                    continue
                else:
                    for ii in items:
                        for ll in ii.get_labels():
                            ll._backwards_compat = value
        self.__dict__[name] = value

    def new_control(self, type, name, attrs,
                    ignore_unknown=False, select_default=False, index=None):
        type = type.lower()
        klass = self.type2class.get(type)
        if klass is None:
            if ignore_unknown:
                klass = IgnoreControl
            else:
                klass = TextControl

        a = attrs.copy()
        if issubclass(klass, ListControl):
            control = klass(type, name, a, select_default, index)
        else:
            control = klass(type, name, a, index)

        if type == "select" and len(attrs) == 1:
            for ii in xrange(len(self.controls)-1, -1, -1):
                ctl = self.controls[ii]
                if ctl.type == "select":
                    ctl.close_control()
                    break

        control.add_to_form(self)
        control._urlparse = self._urlparse
        control._urlunparse = self._urlunparse

    def fixup(self):
        for control in self.controls:
            control.fixup()
        self.backwards_compat = self._backwards_compat

    def __str__(self):
        header = "%s%s %s %s" % (
            (self.name and self.name+" " or ""),
            self.method, self.action, self.enctype)
        rep = [header]
        for control in self.controls:
            rep.append("  %s" % str(control))
        return "<%s>" % "\n".join(rep)


    def __getitem__(self, name):
        return self.find_control(name).value
    def __contains__(self, name):
        return bool(self.find_control(name))
    def __setitem__(self, name, value):
        control = self.find_control(name)
        try:
            control.value = value
        except AttributeError as e:
            raise ValueError(str(e))

    def get_value(self,
                  name=None, type=None, kind=None, id=None, nr=None,
                  by_label=False,  # by_label is deprecated
                  label=None):
        if by_label:
            deprecation("form.get_value_by_label(...)")
        c = self.find_control(name, type, kind, id, label=label, nr=nr)
        if by_label:
            try:
                meth = c.get_value_by_label
            except AttributeError:
                raise NotImplementedError(
                    "control '%s' does not yet support by_label" % c.name)
            else:
                return meth()
        else:
            return c.value
    def set_value(self, value,
                  name=None, type=None, kind=None, id=None, nr=None,
                  by_label=False,  # by_label is deprecated
                  label=None):
        if by_label:
            deprecation("form.get_value_by_label(...)")
        c = self.find_control(name, type, kind, id, label=label, nr=nr)
        if by_label:
            try:
                meth = c.set_value_by_label
            except AttributeError:
                raise NotImplementedError(
                    "control '%s' does not yet support by_label" % c.name)
            else:
                meth(value)
        else:
            c.value = value
    def get_value_by_label(
        self, name=None, type=None, kind=None, id=None, label=None, nr=None):
        c = self.find_control(name, type, kind, id, label=label, nr=nr)
        return c.get_value_by_label()

    def set_value_by_label(
        self, value,
        name=None, type=None, kind=None, id=None, label=None, nr=None):
        c = self.find_control(name, type, kind, id, label=label, nr=nr)
        c.set_value_by_label(value)

    def set_all_readonly(self, readonly):
        for control in self.controls:
            control.readonly = bool(readonly)

    def clear_all(self):
        for control in self.controls:
            control.clear()

    def clear(self,
              name=None, type=None, kind=None, id=None, nr=None, label=None):
        c = self.find_control(name, type, kind, id, label=label, nr=nr)
        c.clear()



    def possible_items(self,  # deprecated
                       name=None, type=None, kind=None, id=None,
                       nr=None, by_label=False, label=None):
        c = self._find_list_control(name, type, kind, id, label, nr)
        return c.possible_items(by_label)

    def set(self, selected, item_name,  # deprecated
            name=None, type=None, kind=None, id=None, nr=None,
            by_label=False, label=None):
        self._find_list_control(name, type, kind, id, label, nr).set(
            selected, item_name, by_label)
    def toggle(self, item_name,  # deprecated
               name=None, type=None, kind=None, id=None, nr=None,
               by_label=False, label=None):
        self._find_list_control(name, type, kind, id, label, nr).toggle(
            item_name, by_label)

    def set_single(self, selected,  # deprecated
                   name=None, type=None, kind=None, id=None,
                   nr=None, by_label=None, label=None):
        self._find_list_control(
            name, type, kind, id, label, nr).set_single(selected)
    def toggle_single(self, name=None, type=None, kind=None, id=None,
                      nr=None, by_label=None, label=None):  # deprecated
        self._find_list_control(name, type, kind, id, label, nr).toggle_single()


    def add_file(self, file_object, content_type=None, filename=None,
                 name=None, id=None, nr=None, label=None):
        self.find_control(name, "file", id=id, label=label, nr=nr).add_file(
            file_object, content_type, filename)


    def click(self, name=None, type=None, id=None, nr=0, coord=(1,1),
              request_class=_urllib.request.Request,
              label=None):
        return self._click(name, type, id, label, nr, coord, "request",
                           self._request_class)

    def click_request_data(self,
                           name=None, type=None, id=None,
                           nr=0, coord=(1,1),
                           request_class=_urllib.request.Request,
                           label=None):
        return self._click(name, type, id, label, nr, coord, "request_data",
                           self._request_class)

    def click_pairs(self, name=None, type=None, id=None,
                    nr=0, coord=(1,1),
                    label=None):
        return self._click(name, type, id, label, nr, coord, "pairs",
                           self._request_class)


    def find_control(self,
                     name=None, type=None, kind=None, id=None,
                     predicate=None, nr=None,
                     label=None):
        if ((name is None) and (type is None) and (kind is None) and
            (id is None) and (label is None) and (predicate is None) and
            (nr is None)):
            raise ValueError(
                "at least one argument must be supplied to specify control")
        return self._find_control(name, type, kind, id, label, predicate, nr)


    def _find_list_control(self,
                           name=None, type=None, kind=None, id=None, 
                           label=None, nr=None):
        if ((name is None) and (type is None) and (kind is None) and
            (id is None) and (label is None) and (nr is None)):
            raise ValueError(
                "at least one argument must be supplied to specify control")

        return self._find_control(name, type, kind, id, label, 
                                  is_listcontrol, nr)

    def _find_control(self, name, type, kind, id, label, predicate, nr):
        if ((name is not None) and (name is not Missing) and
            not isstringlike(name)):
            raise TypeError("control name must be string-like")
        if (type is not None) and not isstringlike(type):
            raise TypeError("control type must be string-like")
        if (kind is not None) and not isstringlike(kind):
            raise TypeError("control kind must be string-like")
        if (id is not None) and not isstringlike(id):
            raise TypeError("control id must be string-like")
        if (label is not None) and not isstringlike(label):
            raise TypeError("control label must be string-like")
        if (predicate is not None) and not callable(predicate):
            raise TypeError("control predicate must be callable")
        if (nr is not None) and nr < 0:
            raise ValueError("control number must be a positive integer")

        orig_nr = nr
        found = None
        ambiguous = False
        if nr is None and self.backwards_compat:
            nr = 0

        for control in self.controls:
            if ((name is not None and name != control.name) and
                (name is not Missing or control.name is not None)):
                continue
            if type is not None and type != control.type:
                continue
            if kind is not None and not control.is_of_kind(kind):
                continue
            if id is not None and id != control.id:
                continue
            if predicate and not predicate(control):
                continue
            if label:
                for l in control.get_labels():
                    if l.text.find(label) > -1:
                        break
                else:
                    continue
            if nr is not None:
                if nr == 0:
                    return control  # early exit: unambiguous due to nr
                nr -= 1
                continue
            if found:
                ambiguous = True
                break
            found = control

        if found and not ambiguous:
            return found

        description = []
        if name is not None: description.append("name %s" % repr(name))
        if type is not None: description.append("type '%s'" % type)
        if kind is not None: description.append("kind '%s'" % kind)
        if id is not None: description.append("id '%s'" % id)
        if label is not None: description.append("label '%s'" % label)
        if predicate is not None:
            description.append("predicate %s" % predicate)
        if orig_nr: description.append("nr %d" % orig_nr)
        description = ", ".join(description)

        if ambiguous:
            raise AmbiguityError("more than one control matching "+description)
        elif not found:
            raise ControlNotFoundError("no control matching "+description)
        assert False

    def _click(self, name, type, id, label, nr, coord, return_type,
               request_class=_urllib.request.Request):
        try:
            control = self._find_control(
                name, type, "clickable", id, label, None, nr)
        except ControlNotFoundError:
            if ((name is not None) or (type is not None) or (id is not None) or
                (nr != 0)):
                raise
            return self._switch_click(return_type, request_class)
        else:
            return control._click(self, coord, return_type, request_class)

    def _pairs(self):
        return [(k, v) for (i, k, v, c_i) in self._pairs_and_controls()]


    def _pairs_and_controls(self):
        pairs = []
        for control_index in xrange(len(self.controls)):
            control = self.controls[control_index]
            for ii, key, val in control._totally_ordered_pairs():
                pairs.append((ii, key, val, control_index))

        pairs.sort()

        return pairs

    def _request_data(self):
        method = self.method.upper()
        parts = self._urlparse(self.action)
        rest, (query, frag) = parts[:-2], parts[-2:]

        if method == "GET":
            self.enctype = "application/x-www-form-urlencoded"  # force it
            parts = rest + (urlencode(self._pairs()), None)
            uri = self._urlunparse(parts)
            return uri, None, []
        elif method == "POST":
            parts = rest + (query, None)
            uri = self._urlunparse(parts)
            if self.enctype == "application/x-www-form-urlencoded":
                return (uri, urlencode(self._pairs()),
                        [("Content-Type", self.enctype)])
            elif self.enctype == "text/plain":
                return (uri, self._pairs(),
                        [("Content-Type", self.enctype)])
            elif self.enctype == "multipart/form-data":
                data = _cStringIO()
                http_hdrs = []
                mw = MimeWriter(data, http_hdrs)
                f = mw.startmultipartbody("form-data", add_to_http_hdrs=True,
                                          prefix=0)
                for ii, k, v, control_index in self._pairs_and_controls():
                    self.controls[control_index]._write_mime_data(mw, k, v)
                mw.lastpart()
                return uri, data.getvalue(), http_hdrs
            else:
                raise ValueError(
                    "unknown POST form encoding type '%s'" % self.enctype)
        else:
            raise ValueError("Unknown method '%s'" % method)

    def _switch_click(self, return_type, request_class=_urllib.request.Request):
        if return_type == "pairs":
            return self._pairs()
        elif return_type == "request_data":
            return self._request_data()
        else:
            req_data = self._request_data()

            req = request_class(req_data[0], req_data[1])
            for key, val in req_data[2]:
                add_hdr = req.add_header
                if key.lower() == "content-type":
                    try:
                        add_hdr = req.add_unredirected_header
                    except AttributeError:
                        pass
                add_hdr(key, val)
            return req
