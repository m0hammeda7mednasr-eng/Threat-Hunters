from __future__ import generators
from __future__ import print_function

__author__ = "Leonard Richardson (leonardr@segfault.org)"
__version__ = "3.2.1b"
__copyright__ = "Copyright (c) 2004-2012 Leonard Richardson"
__license__ = "New-style BSD"

import codecs
import re
import sys

if sys.version_info >= (3, 0):
    xrange = range
    text_type = str
    binary_type = bytes
    basestring = str
    unichr = chr
else:
    text_type = unicode
    binary_type = str

try:
    from html.entities import name2codepoint
except ImportError:
    from htmlentitydefs import name2codepoint

try:
    set
except NameError:
    from sets import Set as set

try:
    import sgmllib
except ImportError:
    from lib.utils import sgmllib

try:
    import markupbase
except ImportError:
    import _markupbase as markupbase

sgmllib.tagfind = re.compile('[a-zA-Z][-_.:a-zA-Z0-9]*')
markupbase._declname_match = re.compile(r'[a-zA-Z][-_.:a-zA-Z0-9]*\s*').match

DEFAULT_OUTPUT_ENCODING = "utf-8"

def _match_css_class(str):
    return re.compile(r"(^|.*\s)%s($|\s)" % re.escape(str))


class PageElement(object):

    def _invert(h):
        i = {}
        for k,v in h.items():
            i[v] = k
        return i

    XML_ENTITIES_TO_SPECIAL_CHARS = { "apos" : "'",
                                      "quot" : '"',
                                      "amp" : "&",
                                      "lt" : "<",
                                      "gt" : ">" }

    XML_SPECIAL_CHARS_TO_ENTITIES = _invert(XML_ENTITIES_TO_SPECIAL_CHARS)

    def setup(self, parent=None, previous=None):
        self.parent = parent
        self.previous = previous
        self.next = None
        self.previousSibling = None
        self.nextSibling = None
        if self.parent and self.parent.contents:
            self.previousSibling = self.parent.contents[-1]
            self.previousSibling.nextSibling = self

    def replaceWith(self, replaceWith):
        oldParent = self.parent
        myIndex = self.parent.index(self)
        if hasattr(replaceWith, "parent")\
                  and replaceWith.parent is self.parent:
            index = replaceWith.parent.index(replaceWith)
            if index and index < myIndex:
                myIndex = myIndex - 1
        self.extract()
        oldParent.insert(myIndex, replaceWith)

    def replaceWithChildren(self):
        myParent = self.parent
        myIndex = self.parent.index(self)
        self.extract()
        reversedChildren = list(self.contents)
        reversedChildren.reverse()
        for child in reversedChildren:
            myParent.insert(myIndex, child)

    def extract(self):
        if self.parent:
            try:
                del self.parent.contents[self.parent.index(self)]
            except ValueError:
                pass

        lastChild = self._lastRecursiveChild()
        nextElement = lastChild.next

        if self.previous:
            self.previous.next = nextElement
        if nextElement:
            nextElement.previous = self.previous
        self.previous = None
        lastChild.next = None

        self.parent = None
        if self.previousSibling:
            self.previousSibling.nextSibling = self.nextSibling
        if self.nextSibling:
            self.nextSibling.previousSibling = self.previousSibling
        self.previousSibling = self.nextSibling = None
        return self

    def _lastRecursiveChild(self):
        lastChild = self
        while hasattr(lastChild, 'contents') and lastChild.contents:
            lastChild = lastChild.contents[-1]
        return lastChild

    def insert(self, position, newChild):
        if isinstance(newChild, basestring) \
            and not isinstance(newChild, NavigableString):
            newChild = NavigableString(newChild)

        position =  min(position, len(self.contents))
        if hasattr(newChild, 'parent') and newChild.parent is not None:
            if newChild.parent is self:
                index = self.index(newChild)
                if index > position:
                    position = position - 1
            newChild.extract()

        newChild.parent = self
        previousChild = None
        if position == 0:
            newChild.previousSibling = None
            newChild.previous = self
        else:
            previousChild = self.contents[position-1]
            newChild.previousSibling = previousChild
            newChild.previousSibling.nextSibling = newChild
            newChild.previous = previousChild._lastRecursiveChild()
        if newChild.previous:
            newChild.previous.next = newChild

        newChildsLastElement = newChild._lastRecursiveChild()

        if position >= len(self.contents):
            newChild.nextSibling = None

            parent = self
            parentsNextSibling = None
            while not parentsNextSibling:
                parentsNextSibling = parent.nextSibling
                parent = parent.parent
                if not parent: # This is the last element in the document.
                    break
            if parentsNextSibling:
                newChildsLastElement.next = parentsNextSibling
            else:
                newChildsLastElement.next = None
        else:
            nextChild = self.contents[position]
            newChild.nextSibling = nextChild
            if newChild.nextSibling:
                newChild.nextSibling.previousSibling = newChild
            newChildsLastElement.next = nextChild

        if newChildsLastElement.next:
            newChildsLastElement.next.previous = newChildsLastElement
        self.contents.insert(position, newChild)

    def append(self, tag):
        self.insert(len(self.contents), tag)

    def findNext(self, name=None, attrs={}, text=None, **kwargs):
        return self._findOne(self.findAllNext, name, attrs, text, **kwargs)

    def findAllNext(self, name=None, attrs={}, text=None, limit=None,
                    **kwargs):
        return self._findAll(name, attrs, text, limit, self.nextGenerator,
                             **kwargs)

    def findNextSibling(self, name=None, attrs={}, text=None, **kwargs):
        return self._findOne(self.findNextSiblings, name, attrs, text,
                             **kwargs)

    def findNextSiblings(self, name=None, attrs={}, text=None, limit=None,
                         **kwargs):
        return self._findAll(name, attrs, text, limit,
                             self.nextSiblingGenerator, **kwargs)
    fetchNextSiblings = findNextSiblings # Compatibility with pre-3.x

    def findPrevious(self, name=None, attrs={}, text=None, **kwargs):
        return self._findOne(self.findAllPrevious, name, attrs, text, **kwargs)

    def findAllPrevious(self, name=None, attrs={}, text=None, limit=None,
                        **kwargs):
        return self._findAll(name, attrs, text, limit, self.previousGenerator,
                           **kwargs)
    fetchPrevious = findAllPrevious # Compatibility with pre-3.x

    def findPreviousSibling(self, name=None, attrs={}, text=None, **kwargs):
        return self._findOne(self.findPreviousSiblings, name, attrs, text,
                             **kwargs)

    def findPreviousSiblings(self, name=None, attrs={}, text=None,
                             limit=None, **kwargs):
        return self._findAll(name, attrs, text, limit,
                             self.previousSiblingGenerator, **kwargs)
    fetchPreviousSiblings = findPreviousSiblings # Compatibility with pre-3.x

    def findParent(self, name=None, attrs={}, **kwargs):
        r = None
        l = self.findParents(name, attrs, 1)
        if l:
            r = l[0]
        return r

    def findParents(self, name=None, attrs={}, limit=None, **kwargs):

        return self._findAll(name, attrs, None, limit, self.parentGenerator,
                             **kwargs)
    fetchParents = findParents # Compatibility with pre-3.x


    def _findOne(self, method, name, attrs, text, **kwargs):
        r = None
        l = method(name, attrs, text, 1, **kwargs)
        if l:
            r = l[0]
        return r

    def _findAll(self, name, attrs, text, limit, generator, **kwargs):

        if isinstance(name, SoupStrainer):
            strainer = name
        elif text is None and not limit and not attrs and not kwargs:
            if name is True:
                return [element for element in generator()
                        if isinstance(element, Tag)]
            elif isinstance(name, basestring):
                return [element for element in generator()
                        if isinstance(element, Tag) and
                        element.name == name]
            else:
                strainer = SoupStrainer(name, attrs, text, **kwargs)
        else:
            strainer = SoupStrainer(name, attrs, text, **kwargs)
        results = ResultSet(strainer)
        g = generator()
        while True:
            try:
                i = next(g)
            except StopIteration:
                break
            if i:
                found = strainer.search(i)
                if found:
                    results.append(found)
                    if limit and len(results) >= limit:
                        break
        return results

    def nextGenerator(self):
        i = self
        while i is not None:
            i = i.next
            yield i

    def nextSiblingGenerator(self):
        i = self
        while i is not None:
            i = i.nextSibling
            yield i

    def previousGenerator(self):
        i = self
        while i is not None:
            i = i.previous
            yield i

    def previousSiblingGenerator(self):
        i = self
        while i is not None:
            i = i.previousSibling
            yield i

    def parentGenerator(self):
        i = self
        while i is not None:
            i = i.parent
            yield i

    def substituteEncoding(self, str, encoding=None):
        encoding = encoding or "utf-8"
        return str.replace("%SOUP-ENCODING%", encoding)

    def toEncoding(self, s, encoding=None):
        if isinstance(s, text_type):
            if encoding:
                s = s.encode(encoding)
        elif isinstance(s, binary_type):
            s = s.encode(encoding or "utf8")
        else:
            s  = self.toEncoding(str(s), encoding or "utf8")
        return s

    BARE_AMPERSAND_OR_BRACKET = re.compile(r"([<>]|&(?!#\d+;|#x[0-9a-fA-F]+;|\w+;))")

    def _sub_entity(self, x):
        return "&" + self.XML_SPECIAL_CHARS_TO_ENTITIES[x.group(0)[0]] + ";"


class NavigableString(text_type, PageElement):

    def __new__(cls, value):
        if isinstance(value, text_type):
            return text_type.__new__(cls, value)
        return text_type.__new__(cls, value, DEFAULT_OUTPUT_ENCODING)

    def __getnewargs__(self):
        return (NavigableString.__str__(self),)

    def __getattr__(self, attr):
        if attr == 'string':
            return self
        else:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    def __unicode__(self):
        return str(self).decode(DEFAULT_OUTPUT_ENCODING)

    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        data = self.BARE_AMPERSAND_OR_BRACKET.sub(self._sub_entity, self)
        if encoding and sys.version_info < (3, 0):
            return data.encode(encoding)
        else:
            return data

class CData(NavigableString):

    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        return "<![CDATA[%s]]>" % NavigableString.__str__(self, encoding)

class ProcessingInstruction(NavigableString):
    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        output = self
        if "%SOUP-ENCODING%" in output:
            output = self.substituteEncoding(output, encoding)
        return "<?%s?>" % self.toEncoding(output, encoding)

class Comment(NavigableString):
    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        return "<!--%s-->" % NavigableString.__str__(self, encoding)

class Declaration(NavigableString):
    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        return "<!%s>" % NavigableString.__str__(self, encoding)

class Tag(PageElement):


    def _convertEntities(self, match):
        try:
            x = match.group(1)
            if self.convertHTMLEntities and x in name2codepoint:
                return unichr(name2codepoint[x])
            elif x in self.XML_ENTITIES_TO_SPECIAL_CHARS:
                if self.convertXMLEntities:
                    return self.XML_ENTITIES_TO_SPECIAL_CHARS[x]
                else:
                    return u'&%s;' % x
            elif len(x) > 0 and x[0] == '#':
                if len(x) > 1 and x[1] == 'x':
                    return unichr(int(x[2:], 16))
                else:
                    return unichr(int(x[1:]))

            elif self.escapeUnrecognizedEntities:
                return u'&amp;%s;' % x

        except ValueError:  # e.g. ValueError: unichr() arg not in range(0x10000)
            pass

        return u'&%s;' % x

    def __init__(self, parser, name, attrs=None, parent=None,
                 previous=None):

        self.parserClass = parser.__class__
        self.isSelfClosing = parser.isSelfClosingTag(name)
        self.name = name
        if attrs is None:
            attrs = []
        elif isinstance(attrs, dict):
            attrs = attrs.items()
        self.attrs = attrs
        self.contents = []
        self.setup(parent, previous)
        self.hidden = False
        self.containsSubstitutions = False
        self.convertHTMLEntities = parser.convertHTMLEntities
        self.convertXMLEntities = parser.convertXMLEntities
        self.escapeUnrecognizedEntities = parser.escapeUnrecognizedEntities

        convert = lambda k_val: (k_val[0],
                                 re.sub(r"&(#\d+|#x[0-9a-fA-F]+|\w+);",
                                     self._convertEntities,
                                     k_val[1]))
        self.attrs = map(convert, self.attrs)

    def getString(self):
        if (len(self.contents) == 1
            and isinstance(self.contents[0], NavigableString)):
            return self.contents[0]

    def setString(self, string):
        self.clear()
        self.append(string)

    string = property(getString, setString)

    def getText(self, separator=u""):
        if not len(self.contents):
            return u""
        stopNode = self._lastRecursiveChild().next
        strings = []
        current = self.contents[0]
        while current and current is not stopNode:
            if isinstance(current, NavigableString):
                strings.append(current.strip())
            current = current.next
        return separator.join(strings)

    text = property(getText)

    def get(self, key, default=None):
        return self._getAttrMap().get(key, default)

    def clear(self):
        for child in self.contents[:]:
            child.extract()

    def index(self, element):
        for i, child in enumerate(self.contents):
            if child is element:
                return i
        raise ValueError("Tag.index: element not in tag")

    def has_key(self, key):
        return self._getAttrMap().has_key(key)

    def __getitem__(self, key):
        return self._getAttrMap()[key]

    def __iter__(self):
        return iter(self.contents)

    def __len__(self):
        return len(self.contents)

    def __contains__(self, x):
        return x in self.contents

    def __nonzero__(self):
        return True

    def __setitem__(self, key, value):
        self._getAttrMap()
        self.attrMap[key] = value
        found = False
        for i in xrange(0, len(self.attrs)):
            if self.attrs[i][0] == key:
                self.attrs[i] = (key, value)
                found = True
        if not found:
            self.attrs.append((key, value))
        self._getAttrMap()[key] = value

    def __delitem__(self, key):
        for item in self.attrs:
            if item[0] == key:
                self.attrs.remove(item)
            self._getAttrMap()
            if self.attrMap.has_key(key):
                del self.attrMap[key]

    def __call__(self, *args, **kwargs):
        return self.findAll(*args, **kwargs)

    def __getattr__(self, tag):
        if len(tag) > 3 and tag.rfind('Tag') == len(tag)-3:
            return self.find(tag[:-3])
        elif tag.find('__') != 0:
            return self.find(tag)
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__, tag))

    def __eq__(self, other):
        if other is self:
            return True
        if not hasattr(other, 'name') or not hasattr(other, 'attrs') or not hasattr(other, 'contents') or self.name != other.name or self.attrs != other.attrs or len(self) != len(other):
            return False
        for i in xrange(0, len(self.contents)):
            if self.contents[i] != other.contents[i]:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __repr__(self, encoding=DEFAULT_OUTPUT_ENCODING):
        return self.__str__(encoding)

    def __unicode__(self):
        return self.__str__(None)

    def __str__(self, encoding=DEFAULT_OUTPUT_ENCODING,
                prettyPrint=False, indentLevel=0):

        encodedName = self.toEncoding(self.name, encoding)

        attrs = []
        if self.attrs:
            for key, val in self.attrs:
                fmt = '%s="%s"'
                if isinstance(val, basestring):
                    if self.containsSubstitutions and '%SOUP-ENCODING%' in val:
                        val = self.substituteEncoding(val, encoding)

                    if '"' in val:
                        fmt = "%s='%s'"
                        if "'" in val:
                            val = val.replace("'", "&squot;")

                    val = self.BARE_AMPERSAND_OR_BRACKET.sub(self._sub_entity, val)

                attrs.append(fmt % (self.toEncoding(key, encoding),
                                    self.toEncoding(val, encoding)))
        close = ''
        closeTag = ''
        if self.isSelfClosing:
            close = ' /'
        else:
            closeTag = '</%s>' % encodedName

        indentTag, indentContents = 0, 0
        if prettyPrint:
            indentTag = indentLevel
            space = (' ' * (indentTag-1))
            indentContents = indentTag + 1
        contents = self.renderContents(encoding, prettyPrint, indentContents)
        if self.hidden:
            s = contents
        else:
            s = []
            attributeString = ''
            if attrs:
                attributeString = ' ' + ' '.join(attrs)
            if prettyPrint:
                s.append(space)
            s.append('<%s%s%s>' % (encodedName, attributeString, close))
            if prettyPrint:
                s.append("\n")
            s.append(contents)
            if prettyPrint and contents and contents[-1] != "\n":
                s.append("\n")
            if prettyPrint and closeTag:
                s.append(space)
            s.append(closeTag)
            if prettyPrint and closeTag and self.nextSibling:
                s.append("\n")
            s = ''.join(s)
        return s

    def decompose(self):
        self.extract()
        if len(self.contents) == 0:
            return
        current = self.contents[0]
        while current is not None:
            next = current.next
            if isinstance(current, Tag):
                del current.contents[:]
            current.parent = None
            current.previous = None
            current.previousSibling = None
            current.next = None
            current.nextSibling = None
            current = next

    def prettify(self, encoding=DEFAULT_OUTPUT_ENCODING):
        return self.__str__(encoding, True)

    def renderContents(self, encoding=DEFAULT_OUTPUT_ENCODING,
                       prettyPrint=False, indentLevel=0):
        s=[]
        for c in self:
            text = None
            if isinstance(c, NavigableString):
                text = c.__str__(encoding)
            elif isinstance(c, Tag):
                s.append(c.__str__(encoding, prettyPrint, indentLevel))
            if text and prettyPrint:
                text = text.strip()
            if text:
                if prettyPrint:
                    s.append(" " * (indentLevel-1))
                s.append(text)
                if prettyPrint:
                    s.append("\n")

        return ''.join(s)


    def find(self, name=None, attrs={}, recursive=True, text=None,
             **kwargs):
        r = None
        l = self.findAll(name, attrs, recursive, text, 1, **kwargs)
        if l:
            r = l[0]
        return r
    findChild = find

    def findAll(self, name=None, attrs={}, recursive=True, text=None,
                limit=None, **kwargs):
        generator = self.recursiveChildGenerator
        if not recursive:
            generator = self.childGenerator
        return self._findAll(name, attrs, text, limit, generator, **kwargs)
    findChildren = findAll

    first = find
    fetch = findAll

    def fetchText(self, text=None, recursive=True, limit=None):
        return self.findAll(text=text, recursive=recursive, limit=limit)

    def firstText(self, text=None, recursive=True):
        return self.find(text=text, recursive=recursive)


    def _getAttrMap(self):
        if not getattr(self, 'attrMap'):
            self.attrMap = {}
            for (key, value) in self.attrs:
                self.attrMap[key] = value
        return self.attrMap

    def childGenerator(self):
        return iter(self.contents)

    def recursiveChildGenerator(self):
        if not len(self.contents):
            return  # Note: https://stackoverflow.com/a/30217723 (PEP 479)
        stopNode = self._lastRecursiveChild().next
        current = self.contents[0]
        while current and current is not stopNode:
            yield current
            current = current.next


class SoupStrainer:

    def __init__(self, name=None, attrs={}, text=None, **kwargs):
        self.name = name
        if isinstance(attrs, basestring):
            kwargs['class'] = _match_css_class(attrs)
            attrs = None
        if kwargs:
            if attrs:
                attrs = attrs.copy()
                attrs.update(kwargs)
            else:
                attrs = kwargs
        self.attrs = attrs
        self.text = text

    def __str__(self):
        if self.text:
            return self.text
        else:
            return "%s|%s" % (self.name, self.attrs)

    def searchTag(self, markupName=None, markupAttrs={}):
        found = None
        markup = None
        if isinstance(markupName, Tag):
            markup = markupName
            markupAttrs = markup
        callFunctionWithTagData = callable(self.name) \
                                and not isinstance(markupName, Tag)

        if (not self.name) \
               or callFunctionWithTagData \
               or (markup and self._matches(markup, self.name)) \
               or (not markup and self._matches(markupName, self.name)):
            if callFunctionWithTagData:
                match = self.name(markupName, markupAttrs)
            else:
                match = True
                markupAttrMap = None
                for attr, matchAgainst in self.attrs.items():
                    if not markupAttrMap:
                         if hasattr(markupAttrs, 'get'):
                            markupAttrMap = markupAttrs
                         else:
                            markupAttrMap = {}
                            for k,v in markupAttrs:
                                markupAttrMap[k] = v
                    attrValue = markupAttrMap.get(attr)
                    if not self._matches(attrValue, matchAgainst):
                        match = False
                        break
            if match:
                if markup:
                    found = markup
                else:
                    found = markupName
        return found

    def search(self, markup):
        found = None
        if hasattr(markup, "__iter__") \
                and not isinstance(markup, Tag):
            for element in markup:
                if isinstance(element, NavigableString) \
                       and self.search(element):
                    found = element
                    break
        elif isinstance(markup, Tag):
            if not self.text:
                found = self.searchTag(markup)
        elif isinstance(markup, NavigableString) or \
                 isinstance(markup, basestring):
            if self._matches(markup, self.text):
                found = markup
        else:
            raise Exception("I don't know how to match against a %s" \
                  % markup.__class__)
        return found

    def _matches(self, markup, matchAgainst):
        result = False
        if matchAgainst is True:
            result = markup is not None
        elif callable(matchAgainst):
            result = matchAgainst(markup)
        else:
            if isinstance(markup, Tag):
                markup = markup.name
            if markup and not isinstance(markup, basestring):
                markup = text_type(markup)
            if hasattr(matchAgainst, 'match'):
                result = markup and matchAgainst.search(markup)
            elif hasattr(matchAgainst, '__iter__'): # list-like
                result = markup in matchAgainst
            elif hasattr(matchAgainst, 'items'):
                result = markup.has_key(matchAgainst)
            elif matchAgainst and isinstance(markup, basestring):
                if isinstance(markup, text_type):
                    matchAgainst = text_type(matchAgainst)
                else:
                    matchAgainst = str(matchAgainst)

            if not result:
                result = matchAgainst == markup
        return result

class ResultSet(list):
    def __init__(self, source):
        list.__init__([])
        self.source = source


def buildTagMap(default, *args):
    built = {}
    for portion in args:
        if hasattr(portion, 'items'):
            for k,v in portion.items():
                built[k] = v
        elif hasattr(portion, '__iter__'): # is a list
            for k in portion:
                built[k] = default
        else:
            built[portion] = default
    return built


class BeautifulStoneSoup(Tag, sgmllib.SGMLParser):


    SELF_CLOSING_TAGS = {}
    NESTABLE_TAGS = {}
    RESET_NESTING_TAGS = {}
    QUOTE_TAGS = {}
    PRESERVE_WHITESPACE_TAGS = []

    MARKUP_MASSAGE = [(re.compile(r'(<[^<>]*)/>'),
                       lambda x: x.group(1) + ' />'),
                      (re.compile(r'<!\s+([^<>]*)>'),
                       lambda x: '<!' + x.group(1) + '>')
                      ]

    ROOT_TAG_NAME = u'[document]'

    HTML_ENTITIES = "html"
    XML_ENTITIES = "xml"
    XHTML_ENTITIES = "xhtml"
    ALL_ENTITIES = XHTML_ENTITIES

    STRIP_ASCII_SPACES = { 9: None, 10: None, 12: None, 13: None, 32: None, }

    def __init__(self, markup="", parseOnlyThese=None, fromEncoding=None,
                 markupMassage=True, smartQuotesTo=XML_ENTITIES,
                 convertEntities=None, selfClosingTags=None, isHTML=False):

        self.parseOnlyThese = parseOnlyThese
        self.fromEncoding = fromEncoding
        self.smartQuotesTo = smartQuotesTo
        self.convertEntities = convertEntities
        if self.convertEntities:
            self.smartQuotesTo = None
            if convertEntities == self.HTML_ENTITIES:
                self.convertXMLEntities = False
                self.convertHTMLEntities = True
                self.escapeUnrecognizedEntities = True
            elif convertEntities == self.XHTML_ENTITIES:
                self.convertXMLEntities = True
                self.convertHTMLEntities = True
                self.escapeUnrecognizedEntities = False
            elif convertEntities == self.XML_ENTITIES:
                self.convertXMLEntities = True
                self.convertHTMLEntities = False
                self.escapeUnrecognizedEntities = False
        else:
            self.convertXMLEntities = False
            self.convertHTMLEntities = False
            self.escapeUnrecognizedEntities = False

        self.instanceSelfClosingTags = buildTagMap(None, selfClosingTags)
        sgmllib.SGMLParser.__init__(self)

        if hasattr(markup, 'read'):        # It's a file-type object.
            markup = markup.read()
        self.markup = markup
        self.markupMassage = markupMassage
        try:
            self._feed(isHTML=isHTML)
        except StopParsing:
            pass
        self.markup = None                 # The markup can now be GCed

    def convert_charref(self, name):
        try:
            n = int(name)
        except ValueError:
            return
        if not 0 <= n <= 127 : # ASCII ends at 127, not 255
            return
        return self.convert_codepoint(n)

    def _feed(self, inDocumentEncoding=None, isHTML=False):
        markup = self.markup
        if isinstance(markup, text_type):
            if not hasattr(self, 'originalEncoding'):
                self.originalEncoding = None
        else:
            dammit = UnicodeDammit\
                     (markup, [self.fromEncoding, inDocumentEncoding],
                      smartQuotesTo=self.smartQuotesTo, isHTML=isHTML)
            markup = dammit.unicode
            self.originalEncoding = dammit.originalEncoding
            self.declaredHTMLEncoding = dammit.declaredHTMLEncoding
        if markup:
            if self.markupMassage:
                if not hasattr(self.markupMassage, "__iter__"):
                    self.markupMassage = self.MARKUP_MASSAGE
                for fix, m in self.markupMassage:
                    markup = fix.sub(m, markup)
                del(self.markupMassage)
        self.reset()

        sgmllib.SGMLParser.feed(self, markup)
        self.endData()
        while self.currentTag.name != self.ROOT_TAG_NAME:
            self.popTag()

    def __getattr__(self, methodName):

        if methodName.startswith('start_') or methodName.startswith('end_') \
               or methodName.startswith('do_'):
            return sgmllib.SGMLParser.__getattr__(self, methodName)
        elif not methodName.startswith('__'):
            return Tag.__getattr__(self, methodName)
        else:
            raise AttributeError

    def isSelfClosingTag(self, name):
        return name in self.SELF_CLOSING_TAGS \
               or name in self.instanceSelfClosingTags

    def reset(self):
        Tag.__init__(self, self, self.ROOT_TAG_NAME)
        self.hidden = 1
        sgmllib.SGMLParser.reset(self)
        self.currentData = []
        self.currentTag = None
        self.tagStack = []
        self.quoteStack = []
        self.pushTag(self)

    def popTag(self):
        tag = self.tagStack.pop()

        if self.tagStack:
            self.currentTag = self.tagStack[-1]
        return self.currentTag

    def pushTag(self, tag):
        if self.currentTag:
            self.currentTag.contents.append(tag)
        self.tagStack.append(tag)
        self.currentTag = self.tagStack[-1]

    def endData(self, containerClass=NavigableString):
        if self.currentData:
            currentData = u''.join(self.currentData)
            if (currentData.translate(self.STRIP_ASCII_SPACES) == '' and
                not set([tag.name for tag in self.tagStack]).intersection(
                    self.PRESERVE_WHITESPACE_TAGS)):
                if '\n' in currentData:
                    currentData = '\n'
                else:
                    currentData = ' '
            self.currentData = []
            if self.parseOnlyThese and len(self.tagStack) <= 1 and \
                   (not self.parseOnlyThese.text or \
                    not self.parseOnlyThese.search(currentData)):
                return
            o = containerClass(currentData)
            o.setup(self.currentTag, self.previous)
            if self.previous:
                self.previous.next = o
            self.previous = o
            self.currentTag.contents.append(o)


    def _popToTag(self, name, inclusivePop=True):
        if name == self.ROOT_TAG_NAME:
            return

        numPops = 0
        mostRecentTag = None
        for i in xrange(len(self.tagStack)-1, 0, -1):
            if name == self.tagStack[i].name:
                numPops = len(self.tagStack)-i
                break
        if not inclusivePop:
            numPops = numPops - 1

        for i in xrange(0, numPops):
            mostRecentTag = self.popTag()
        return mostRecentTag

    def _smartPop(self, name):


        nestingResetTriggers = self.NESTABLE_TAGS.get(name)
        isNestable = nestingResetTriggers != None
        isResetNesting = name in self.RESET_NESTING_TAGS
        popTo = None
        inclusive = True
        for i in xrange(len(self.tagStack)-1, 0, -1):
            p = self.tagStack[i]
            if (not p or p.name == name) and not isNestable:
                popTo = name
                break
            if (nestingResetTriggers is not None
                and p.name in nestingResetTriggers) \
                or (nestingResetTriggers is None and isResetNesting
                    and p.name in self.RESET_NESTING_TAGS):

                popTo = p.name
                inclusive = False
                break
            p = p.parent
        if popTo:
            self._popToTag(popTo, inclusive)

    def unknown_starttag(self, name, attrs, selfClosing=0):
        if self.quoteStack:
            attrs = ''.join([' %s="%s"' % (x, y) for x, y in attrs])
            self.handle_data('<%s%s>' % (name, attrs))
            return
        self.endData()

        if not self.isSelfClosingTag(name) and not selfClosing:
            self._smartPop(name)

        if self.parseOnlyThese and len(self.tagStack) <= 1 \
               and (self.parseOnlyThese.text or not self.parseOnlyThese.searchTag(name, attrs)):
            return

        tag = Tag(self, name, attrs, self.currentTag, self.previous)
        if self.previous:
            self.previous.next = tag
        self.previous = tag
        self.pushTag(tag)
        if selfClosing or self.isSelfClosingTag(name):
            self.popTag()
        if name in self.QUOTE_TAGS:
            self.quoteStack.append(name)
            self.literal = 1
        return tag

    def unknown_endtag(self, name):
        if self.quoteStack and self.quoteStack[-1] != name:
            self.handle_data('</%s>' % name)
            return
        self.endData()
        self._popToTag(name)
        if self.quoteStack and self.quoteStack[-1] == name:
            self.quoteStack.pop()
            self.literal = (len(self.quoteStack) > 0)

    def handle_data(self, data):
        self.currentData.append(data)

    def _toStringSubclass(self, text, subclass):
        self.endData()
        self.handle_data(text)
        self.endData(subclass)

    def handle_pi(self, text):
        if text[:3] == "xml":
            text = u"xml version='1.0' encoding='%SOUP-ENCODING%'"
        self._toStringSubclass(text, ProcessingInstruction)

    def handle_comment(self, text):
        self._toStringSubclass(text, Comment)

    def handle_charref(self, ref):
        if self.convertEntities:
            data = unichr(int(ref))
        else:
            data = '&#%s;' % ref
        self.handle_data(data)

    def handle_entityref(self, ref):
        data = None
        if self.convertHTMLEntities:
            try:
                data = unichr(name2codepoint[ref])
            except KeyError:
                pass

        if not data and self.convertXMLEntities:
                data = self.XML_ENTITIES_TO_SPECIAL_CHARS.get(ref)

        if not data and self.convertHTMLEntities and \
            not self.XML_ENTITIES_TO_SPECIAL_CHARS.get(ref):
                data = "&amp;%s" % ref
        if not data:
            data = "&%s;" % ref
        self.handle_data(data)

    def handle_decl(self, data):
        self._toStringSubclass(data, Declaration)

    def parse_declaration(self, i):
        j = None
        if self.rawdata[i:i+9] == '<![CDATA[':
             k = self.rawdata.find(']]>', i)
             if k == -1:
                 k = len(self.rawdata)
             data = self.rawdata[i+9:k]
             j = k+3
             self._toStringSubclass(data, CData)
        else:
            try:
                j = sgmllib.SGMLParser.parse_declaration(self, i)
            except sgmllib.SGMLParseError:
                toHandle = self.rawdata[i:]
                self.handle_data(toHandle)
                j = i + len(toHandle)
        return j

class BeautifulSoup(BeautifulStoneSoup):


    def __init__(self, *args, **kwargs):
        if 'smartQuotesTo' not in kwargs:
            kwargs['smartQuotesTo'] = self.HTML_ENTITIES
        kwargs['isHTML'] = True
        BeautifulStoneSoup.__init__(self, *args, **kwargs)

    SELF_CLOSING_TAGS = buildTagMap(None,
                                    ('br' , 'hr', 'input', 'img', 'meta',
                                    'spacer', 'link', 'frame', 'base', 'col'))

    PRESERVE_WHITESPACE_TAGS = set(['pre', 'textarea'])

    QUOTE_TAGS = {'script' : None, 'textarea' : None}

    NESTABLE_INLINE_TAGS = ('span', 'font', 'q', 'object', 'bdo', 'sub', 'sup',
                            'center')

    NESTABLE_BLOCK_TAGS = ('blockquote', 'div', 'fieldset', 'ins', 'del')

    NESTABLE_LIST_TAGS = { 'ol' : [],
                           'ul' : [],
                           'li' : ['ul', 'ol'],
                           'dl' : [],
                           'dd' : ['dl'],
                           'dt' : ['dl'] }

    NESTABLE_TABLE_TAGS = {'table' : [],
                           'tr' : ['table', 'tbody', 'tfoot', 'thead'],
                           'td' : ['tr'],
                           'th' : ['tr'],
                           'thead' : ['table'],
                           'tbody' : ['table'],
                           'tfoot' : ['table'],
                           }

    NON_NESTABLE_BLOCK_TAGS = ('address', 'form', 'p', 'pre')

    RESET_NESTING_TAGS = buildTagMap(None, NESTABLE_BLOCK_TAGS, 'noscript',
                                     NON_NESTABLE_BLOCK_TAGS,
                                     NESTABLE_LIST_TAGS,
                                     NESTABLE_TABLE_TAGS)

    NESTABLE_TAGS = buildTagMap([], NESTABLE_INLINE_TAGS, NESTABLE_BLOCK_TAGS,
                                NESTABLE_LIST_TAGS, NESTABLE_TABLE_TAGS)

    CHARSET_RE = re.compile(r"((^|;)\s*charset=)([^;]*)", re.M)

    def start_meta(self, attrs):
        httpEquiv = None
        contentType = None
        contentTypeIndex = None
        tagNeedsEncodingSubstitution = False

        for i in xrange(0, len(attrs)):
            key, value = attrs[i]
            key = key.lower()
            if key == 'http-equiv':
                httpEquiv = value
            elif key == 'content':
                contentType = value
                contentTypeIndex = i

        if httpEquiv and contentType: # It's an interesting meta tag.
            match = self.CHARSET_RE.search(contentType)
            if match:
                if (self.declaredHTMLEncoding is not None or
                    self.originalEncoding == self.fromEncoding):
                    def rewrite(match):
                        return match.group(1) + "%SOUP-ENCODING%"
                    newAttr = self.CHARSET_RE.sub(rewrite, contentType)
                    attrs[contentTypeIndex] = (attrs[contentTypeIndex][0],
                                               newAttr)
                    tagNeedsEncodingSubstitution = True
                else:
                    newCharset = match.group(3)
                    if newCharset and newCharset != self.originalEncoding:
                        self.declaredHTMLEncoding = newCharset
                        self._feed(self.declaredHTMLEncoding)
                        raise StopParsing
                    pass
        tag = self.unknown_starttag("meta", attrs)
        if tag and tagNeedsEncodingSubstitution:
            tag.containsSubstitutions = True

class StopParsing(Exception):
    pass

class ICantBelieveItsBeautifulSoup(BeautifulSoup):


    I_CANT_BELIEVE_THEYRE_NESTABLE_INLINE_TAGS = \
     ('em', 'big', 'i', 'small', 'tt', 'abbr', 'acronym', 'strong',
      'cite', 'code', 'dfn', 'kbd', 'samp', 'strong', 'var', 'b',
      'big')

    I_CANT_BELIEVE_THEYRE_NESTABLE_BLOCK_TAGS = ('noscript',)

    NESTABLE_TAGS = buildTagMap([], BeautifulSoup.NESTABLE_TAGS,
                                I_CANT_BELIEVE_THEYRE_NESTABLE_BLOCK_TAGS,
                                I_CANT_BELIEVE_THEYRE_NESTABLE_INLINE_TAGS)

class MinimalSoup(BeautifulSoup):

    RESET_NESTING_TAGS = buildTagMap('noscript')
    NESTABLE_TAGS = {}

class BeautifulSOAP(BeautifulStoneSoup):

    def popTag(self):
        if len(self.tagStack) > 1:
            tag = self.tagStack[-1]
            parent = self.tagStack[-2]
            parent._getAttrMap()
            if (isinstance(tag, Tag) and len(tag.contents) == 1 and
                isinstance(tag.contents[0], NavigableString) and
                not parent.attrMap.has_key(tag.name)):
                parent[tag.name] = tag.contents[0]
        BeautifulStoneSoup.popTag(self)

class RobustXMLParser(BeautifulStoneSoup):
    pass
class RobustHTMLParser(BeautifulSoup):
    pass
class RobustWackAssHTMLParser(ICantBelieveItsBeautifulSoup):
    pass
class RobustInsanelyWackAssHTMLParser(MinimalSoup):
    pass
class SimplifyingSOAPParser(BeautifulSOAP):
    pass


try:
    import chardet
except ImportError:
    chardet = None

try:
    import cjkcodecs.aliases
except ImportError:
    pass
try:
    import iconv_codec
except ImportError:
    pass

class UnicodeDammit:

    CHARSET_ALIASES = { "macintosh" : "mac-roman",
                        "x-sjis" : "shift-jis" }

    def __init__(self, markup, overrideEncodings=[],
                 smartQuotesTo='xml', isHTML=False):
        self.declaredHTMLEncoding = None
        self.markup, documentEncoding, sniffedEncoding = \
                     self._detectEncoding(markup, isHTML)
        self.smartQuotesTo = smartQuotesTo
        self.triedEncodings = []
        if markup == '' or isinstance(markup, text_type):
            self.originalEncoding = None
            self.unicode = text_type(markup)
            return

        u = None
        for proposedEncoding in overrideEncodings:
            u = self._convertFrom(proposedEncoding)
            if u: break
        if not u:
            for proposedEncoding in (documentEncoding, sniffedEncoding):
                u = self._convertFrom(proposedEncoding)
                if u: break

        if not u and chardet and not isinstance(self.markup, text_type):
            u = self._convertFrom(chardet.detect(self.markup)['encoding'])

        if not u:
            for proposed_encoding in ("utf-8", "windows-1252"):
                u = self._convertFrom(proposed_encoding)
                if u: break

        self.unicode = u
        if not u: self.originalEncoding = None

    def _subMSChar(self, orig):
        sub = self.MS_CHARS.get(orig)
        if isinstance(sub, tuple):
            if self.smartQuotesTo == 'xml':
                sub = '&#x%s;' % sub[1]
            else:
                sub = '&%s;' % sub[0]
        return sub

    def _convertFrom(self, proposed):
        proposed = self.find_codec(proposed)
        if not proposed or proposed in self.triedEncodings:
            return None
        self.triedEncodings.append(proposed)
        markup = self.markup

        if self.smartQuotesTo and proposed.lower() in("windows-1252",
                                                      "iso-8859-1",
                                                      "iso-8859-2"):
            markup = re.compile("([\x80-\x9f])").sub \
                     (lambda x: self._subMSChar(x.group(1)),
                      markup)

        try:
            u = self._toUnicode(markup, proposed)
            self.markup = u
            self.originalEncoding = proposed
        except Exception as e:
            return None
        return self.markup

    def _toUnicode(self, data, encoding):

        if (len(data) >= 4) and (data[:2] == '\xfe\xff') \
               and (data[2:4] != '\x00\x00'):
            encoding = 'utf-16be'
            data = data[2:]
        elif (len(data) >= 4) and (data[:2] == '\xff\xfe') \
                 and (data[2:4] != '\x00\x00'):
            encoding = 'utf-16le'
            data = data[2:]
        elif data[:3] == '\xef\xbb\xbf':
            encoding = 'utf-8'
            data = data[3:]
        elif data[:4] == '\x00\x00\xfe\xff':
            encoding = 'utf-32be'
            data = data[4:]
        elif data[:4] == '\xff\xfe\x00\x00':
            encoding = 'utf-32le'
            data = data[4:]
        newdata = text_type(data, encoding)
        return newdata

    def _detectEncoding(self, xml_data, isHTML=False):
        xml_encoding = sniffed_xml_encoding = None
        try:
            if xml_data[:4] == '\x4c\x6f\xa7\x94':
                xml_data = self._ebcdic_to_ascii(xml_data)
            elif xml_data[:4] == '\x00\x3c\x00\x3f':
                sniffed_xml_encoding = 'utf-16be'
                xml_data = text_type(xml_data, 'utf-16be').encode('utf-8')
            elif (len(xml_data) >= 4) and (xml_data[:2] == '\xfe\xff') \
                     and (xml_data[2:4] != '\x00\x00'):
                sniffed_xml_encoding = 'utf-16be'
                xml_data = text_type(xml_data[2:], 'utf-16be').encode('utf-8')
            elif xml_data[:4] == '\x3c\x00\x3f\x00':
                sniffed_xml_encoding = 'utf-16le'
                xml_data = text_type(xml_data, 'utf-16le').encode('utf-8')
            elif (len(xml_data) >= 4) and (xml_data[:2] == '\xff\xfe') and \
                     (xml_data[2:4] != '\x00\x00'):
                sniffed_xml_encoding = 'utf-16le'
                xml_data = text_type(xml_data[2:], 'utf-16le').encode('utf-8')
            elif xml_data[:4] == '\x00\x00\x00\x3c':
                sniffed_xml_encoding = 'utf-32be'
                xml_data = text_type(xml_data, 'utf-32be').encode('utf-8')
            elif xml_data[:4] == '\x3c\x00\x00\x00':
                sniffed_xml_encoding = 'utf-32le'
                xml_data = text_type(xml_data, 'utf-32le').encode('utf-8')
            elif xml_data[:4] == '\x00\x00\xfe\xff':
                sniffed_xml_encoding = 'utf-32be'
                xml_data = text_type(xml_data[4:], 'utf-32be').encode('utf-8')
            elif xml_data[:4] == '\xff\xfe\x00\x00':
                sniffed_xml_encoding = 'utf-32le'
                xml_data = text_type(xml_data[4:], 'utf-32le').encode('utf-8')
            elif xml_data[:3] == '\xef\xbb\xbf':
                sniffed_xml_encoding = 'utf-8'
                xml_data = text_type(xml_data[3:], 'utf-8').encode('utf-8')
            else:
                sniffed_xml_encoding = 'ascii'
                pass
        except:
            xml_encoding_match = None
        xml_encoding_match = re.compile(
            r'^<\?.*encoding=[\'"](.*?)[\'"].*\?>').match(xml_data)
        if not xml_encoding_match and isHTML:
            regexp = re.compile(r'<\s*meta[^>]+charset=([^>]*?)[;\'">]', re.I)
            xml_encoding_match = regexp.search(xml_data)
        if xml_encoding_match is not None:
            xml_encoding = xml_encoding_match.groups()[0].lower()
            if isHTML:
                self.declaredHTMLEncoding = xml_encoding
            if sniffed_xml_encoding and \
               (xml_encoding in ('iso-10646-ucs-2', 'ucs-2', 'csunicode',
                                 'iso-10646-ucs-4', 'ucs-4', 'csucs4',
                                 'utf-16', 'utf-32', 'utf_16', 'utf_32',
                                 'utf16', 'u16')):
                xml_encoding = sniffed_xml_encoding
        return xml_data, xml_encoding, sniffed_xml_encoding


    def find_codec(self, charset):
        return self._codec(self.CHARSET_ALIASES.get(charset, charset)) \
               or (charset and self._codec(charset.replace("-", ""))) \
               or (charset and self._codec(charset.replace("-", "_"))) \
               or charset

    def _codec(self, charset):
        if not charset: return charset
        codec = None
        try:
            codecs.lookup(charset)
            codec = charset
        except (LookupError, ValueError):
            pass
        return codec

    EBCDIC_TO_ASCII_MAP = None
    def _ebcdic_to_ascii(self, s):
        c = self.__class__
        if not c.EBCDIC_TO_ASCII_MAP:
            emap = (0,1,2,3,156,9,134,127,151,141,142,11,12,13,14,15,
                    16,17,18,19,157,133,8,135,24,25,146,143,28,29,30,31,
                    128,129,130,131,132,10,23,27,136,137,138,139,140,5,6,7,
                    144,145,22,147,148,149,150,4,152,153,154,155,20,21,158,26,
                    32,160,161,162,163,164,165,166,167,168,91,46,60,40,43,33,
                    38,169,170,171,172,173,174,175,176,177,93,36,42,41,59,94,
                    45,47,178,179,180,181,182,183,184,185,124,44,37,95,62,63,
                    186,187,188,189,190,191,192,193,194,96,58,35,64,39,61,34,
                    195,97,98,99,100,101,102,103,104,105,196,197,198,199,200,
                    201,202,106,107,108,109,110,111,112,113,114,203,204,205,
                    206,207,208,209,126,115,116,117,118,119,120,121,122,210,
                    211,212,213,214,215,216,217,218,219,220,221,222,223,224,
                    225,226,227,228,229,230,231,123,65,66,67,68,69,70,71,72,
                    73,232,233,234,235,236,237,125,74,75,76,77,78,79,80,81,
                    82,238,239,240,241,242,243,92,159,83,84,85,86,87,88,89,
                    90,244,245,246,247,248,249,48,49,50,51,52,53,54,55,56,57,
                    250,251,252,253,254,255)
            import string
            c.EBCDIC_TO_ASCII_MAP = string.maketrans( \
            ''.join(map(chr, xrange(256))), ''.join(map(chr, emap)))
        return s.translate(c.EBCDIC_TO_ASCII_MAP)

    MS_CHARS = { '\x80' : ('euro', '20AC'),
                 '\x81' : ' ',
                 '\x82' : ('sbquo', '201A'),
                 '\x83' : ('fnof', '192'),
                 '\x84' : ('bdquo', '201E'),
                 '\x85' : ('hellip', '2026'),
                 '\x86' : ('dagger', '2020'),
                 '\x87' : ('Dagger', '2021'),
                 '\x88' : ('circ', '2C6'),
                 '\x89' : ('permil', '2030'),
                 '\x8A' : ('Scaron', '160'),
                 '\x8B' : ('lsaquo', '2039'),
                 '\x8C' : ('OElig', '152'),
                 '\x8D' : '?',
                 '\x8E' : ('#x17D', '17D'),
                 '\x8F' : '?',
                 '\x90' : '?',
                 '\x91' : ('lsquo', '2018'),
                 '\x92' : ('rsquo', '2019'),
                 '\x93' : ('ldquo', '201C'),
                 '\x94' : ('rdquo', '201D'),
                 '\x95' : ('bull', '2022'),
                 '\x96' : ('ndash', '2013'),
                 '\x97' : ('mdash', '2014'),
                 '\x98' : ('tilde', '2DC'),
                 '\x99' : ('trade', '2122'),
                 '\x9a' : ('scaron', '161'),
                 '\x9b' : ('rsaquo', '203A'),
                 '\x9c' : ('oelig', '153'),
                 '\x9d' : '?',
                 '\x9e' : ('#x17E', '17E'),
                 '\x9f' : ('Yuml', ''),}



if __name__ == '__main__':
    soup = BeautifulSoup(sys.stdin)
    print(soup.prettify())
