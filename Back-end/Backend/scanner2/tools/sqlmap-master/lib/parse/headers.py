import os

from lib.core.common import parseXmlFile
from lib.core.data import kb
from lib.core.data import paths
from lib.parse.handler import FingerprintHandler

def headersParser(headers):

    if not kb.headerPaths:
        kb.headerPaths = {
            "microsoftsharepointteamservices": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "sharepoint.xml"),
            "server": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "server.xml"),
            "servlet-engine": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "servlet-engine.xml"),
            "set-cookie": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "set-cookie.xml"),
            "x-aspnet-version": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-aspnet-version.xml"),
            "x-powered-by": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-powered-by.xml"),
        }

    for header, xmlfile in kb.headerPaths.items():
        if header in headers:
            handler = FingerprintHandler(headers[header], kb.headersFp)
            parseXmlFile(xmlfile, handler)
            parseXmlFile(paths.GENERIC_XML, handler)
