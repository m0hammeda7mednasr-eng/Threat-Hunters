import codecs
import os
import platform
import random
import re
import string
import sys
import time

from lib.core.enums import DBMS
from lib.core.enums import DBMS_DIRECTORY_NAME
from lib.core.enums import OS
from thirdparty import six

VERSION = "1.10.4.13"
TYPE = "dev" if VERSION.count('.') > 2 and VERSION.split('.')[-1] != '0' else "stable"
TYPE_COLORS = {"dev": 33, "stable": 90, "pip": 34}
VERSION_STRING = "sqlmap/%s#%s" % ('.'.join(VERSION.split('.')[:-1]) if VERSION.count('.') > 2 and VERSION.split('.')[-1] == '0' else VERSION, TYPE)
DESCRIPTION = "automatic SQL injection and database takeover tool"
SITE = "https://sqlmap.org"
DEFAULT_USER_AGENT = "%s (%s)" % (VERSION_STRING, SITE)
DEV_EMAIL_ADDRESS = "dev@sqlmap.org"
ISSUES_PAGE = "https://github.com/sqlmapproject/sqlmap/issues/new"
GIT_REPOSITORY = "https://github.com/sqlmapproject/sqlmap.git"
GIT_PAGE = "https://github.com/sqlmapproject/sqlmap"
WIKI_PAGE = "https://github.com/sqlmapproject/sqlmap/wiki/"
ZIPBALL_PAGE = "https://github.com/sqlmapproject/sqlmap/zipball/master"

BANNER = """\033[01;33m\
        ___
       __H__
 ___ ___[.]_____ ___ ___  \033[01;37m{\033[01;%dm%s\033[01;37m}\033[01;33m
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   \033[0m\033[4;37m%s\033[0m\n
""" % (TYPE_COLORS.get(TYPE, 31), VERSION_STRING.split('/')[-1], SITE)

DIFF_TOLERANCE = 0.05
CONSTANT_RATIO = 0.9

IPS_WAF_CHECK_RATIO = 0.5

IPS_WAF_CHECK_TIMEOUT = 10

LIVE_COOKIES_TIMEOUT = 120

LOWER_RATIO_BOUND = 0.02
UPPER_RATIO_BOUND = 0.98

DUMMY_JUNK = "fooj0Zo4"

PARAMETER_AMP_MARKER = "__PARAMETER_AMP__"
PARAMETER_SEMICOLON_MARKER = "__PARAMETER_SEMICOLON__"
BOUNDARY_BACKSLASH_MARKER = "__BOUNDARY_BACKSLASH__"
PARAMETER_PERCENTAGE_MARKER = "__PARAMETER_PERCENTAGE__"
PARTIAL_VALUE_MARKER = "__PARTIAL_VALUE__"
PARTIAL_HEX_VALUE_MARKER = "__PARTIAL_HEX_VALUE__"
URI_QUESTION_MARKER = "__URI_QUESTION__"
ASTERISK_MARKER = "__ASTERISK__"
REPLACEMENT_MARKER = "__REPLACEMENT__"
BOUNDED_BASE64_MARKER = "__BOUNDED_BASE64__"
BOUNDED_INJECTION_MARKER = "__BOUNDED_INJECTION__"
SAFE_VARIABLE_MARKER = "__SAFE_VARIABLE__"
SAFE_HEX_MARKER = "__SAFE_HEX__"
DOLLAR_MARKER = "__DOLLAR__"

RANDOM_INTEGER_MARKER = "[RANDINT]"
RANDOM_STRING_MARKER = "[RANDSTR]"
SLEEP_TIME_MARKER = "[SLEEPTIME]"
INFERENCE_MARKER = "[INFERENCE]"
SINGLE_QUOTE_MARKER = "[SINGLE_QUOTE]"
GENERIC_SQL_COMMENT_MARKER = "[GENERIC_SQL_COMMENT]"

PAYLOAD_DELIMITER = "__PAYLOAD_DELIMITER__"
CHAR_INFERENCE_MARK = "%c"
PRINTABLE_CHAR_REGEX = r"[^\x00-\x1f\x7f-\xff]"

SELECT_FROM_TABLE_REGEX = r"\bSELECT\b.+?\bFROM\s+(?P<result>([\w.]|`[^`<>]+`)+)"

TEXT_CONTENT_TYPE_REGEX = r"(?i)(text|form|message|xml|javascript|ecmascript|json)"

PERMISSION_DENIED_REGEX = r"\b(?P<result>(command|permission|access|user)\s*(was|is|has been)?\s*(denied|forbidden|unauthorized|rejected|not allowed))"

GENERIC_PROTECTION_REGEX = r"(?i)\b(rejected|blocked|protection|incident|denied|detected|dangerous|firewall)\b"

FUZZ_UNION_ERROR_REGEX = r"(?i)data\s?type|mismatch|comparable|compatible|conversion|convert|failed|error|unexpected"

FUZZ_UNION_MAX_COLUMNS = 10

MAX_CONNECTIONS_REGEX = r"\bmax.{1,100}\bconnection"

MAX_CONSECUTIVE_CONNECTION_ERRORS = 15

PRECONNECT_CANDIDATE_TIMEOUT = 10

PRECONNECT_INCOMPATIBLE_SERVERS = ("SimpleHTTP", "BaseHTTP")

IDENTYWAF_PARSE_COUNT_LIMIT = 10

IDENTYWAF_PARSE_PAGE_LIMIT = 4 * 1024

MAX_MURPHY_SLEEP_TIME = 3

GOOGLE_REGEX = r"webcache\.googleusercontent\.com/search\?q=cache:[^:]+:([^+]+)\+&amp;cd=|url\?\w+=((?![^>]+webcache\.googleusercontent\.com)http[^>]+)&(sa=U|rct=j)"

GOOGLE_CONSENT_COOKIE = "CONSENT=YES+shp.gws-%s-0-RC1.%s+FX+740" % (time.strftime("%Y%m%d"), "".join(random.sample(string.ascii_lowercase, 2)))

DUCKDUCKGO_REGEX = r'<a class="result__url" href="(htt[^"]+)'

BING_REGEX = r'<h2><a href="([^"]+)" h='

DUMMY_SEARCH_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"

TEXT_TAG_REGEX = r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h[1-6]|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"

IP_ADDRESS_REGEX = r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"

BLOCKED_IP_REGEX = r"(?i)(\A|\b)ip\b.*\b(banned|blocked|block\s?list|firewall)"

CONCAT_ROW_DELIMITER = ','
CONCAT_VALUE_DELIMITER = '|'

TIME_STDEV_COEFF = 7

MIN_VALID_DELAYED_RESPONSE = 0.5

WARN_TIME_STDEV = 0.5

UNION_MIN_RESPONSE_CHARS = 10

UNION_STDEV_COEFF = 7

TIME_DELAY_CANDIDATES = 3

HTTP_ACCEPT_HEADER_VALUE = "*/*"

HTTP_ACCEPT_ENCODING_HEADER_VALUE = "gzip,deflate"

BACKDOOR_RUN_CMD_TIMEOUT = 5

THREAD_FINALIZATION_TIMEOUT = 1

MAX_TECHNIQUES_PER_VALUE = 2

MAX_BUFFERED_PARTIAL_UNION_LENGTH = 1024

MAX_CACHE_ITEMS = 1024

METADB_SUFFIX = "_masterdb"

PUSH_VALUE_EXCEPTION_RETRY_COUNT = 3

MIN_TIME_RESPONSES = 30

MAX_TIME_RESPONSES = 200

MIN_UNION_RESPONSES = 5

INFERENCE_BLANK_BREAK = 5

INFERENCE_UNKNOWN_CHAR = '?'

INFERENCE_GREATER_CHAR = ">"

INFERENCE_GREATER_EQUALS_CHAR = ">="

INFERENCE_EQUALS_CHAR = "="

INFERENCE_NOT_EQUALS_CHAR = "!="

UNKNOWN_DBMS = "Unknown"

UNKNOWN_DBMS_VERSION = "Unknown"

DYNAMICITY_BOUNDARY_LENGTH = 20

DUMMY_USER_PREFIX = "__dummy__"

DEFAULT_PAGE_ENCODING = "iso-8859-1"

try:
    codecs.lookup(DEFAULT_PAGE_ENCODING)
except LookupError:
    DEFAULT_PAGE_ENCODING = "utf8"

STDIN_PIPE_DASH = '-'

DUMMY_URL = "http://foo/bar?id=1"

WEBSOCKET_INITIAL_TIMEOUT = 3

PLATFORM = os.name
PYVERSION = sys.version.split()[0]
IS_WIN = PLATFORM == "nt"
IS_PYPY = platform.python_implementation() == "PyPy"

IS_TTY = hasattr(sys.stdout, "fileno") and os.isatty(sys.stdout.fileno())

MSSQL_SYSTEM_DBS = ("Northwind", "master", "model", "msdb", "pubs", "tempdb", "Resource", "ReportServer", "ReportServerTempDB", "distribution", "mssqlsystemresource")
MYSQL_SYSTEM_DBS = ("information_schema", "mysql", "performance_schema", "sys", "ndbinfo")
PGSQL_SYSTEM_DBS = ("postgres", "template0", "template1", "information_schema", "pg_catalog", "pg_toast", "pgagent")
ORACLE_SYSTEM_DBS = ("ADAMS", "ANONYMOUS", "APEX_030200", "APEX_PUBLIC_USER", "APPQOSSYS", "AURORA$ORB$UNAUTHENTICATED", "AWR_STAGE", "BI", "BLAKE", "CLARK", "CSMIG", "CTXSYS", "DBSNMP", "DEMO", "DIP", "DMSYS", "DSSYS", "EXFSYS", "FLOWS_%", "FLOWS_FILES", "HR", "IX", "JONES", "LBACSYS", "MDDATA", "MDSYS", "MGMT_VIEW", "OC", "OE", "OLAPSYS", "ORACLE_OCM", "ORDDATA", "ORDPLUGINS", "ORDSYS", "OUTLN", "OWBSYS", "PAPER", "PERFSTAT", "PM", "SCOTT", "SH", "SI_INFORMTN_SCHEMA", "SPATIAL_CSW_ADMIN_USR", "SPATIAL_WFS_ADMIN_USR", "SYS", "SYSMAN", "SYSTEM", "TRACESVR", "TSMSYS", "WK_TEST", "WKPROXY", "WKSYS", "WMSYS", "XDB", "XS$NULL")
SQLITE_SYSTEM_DBS = ("sqlite_master", "sqlite_temp_master")
ACCESS_SYSTEM_DBS = ("MSysAccessObjects", "MSysACEs", "MSysObjects", "MSysQueries", "MSysRelationships", "MSysAccessStorage", "MSysAccessXML", "MSysModules", "MSysModules2", "MSysNavPaneGroupCategories", "MSysNavPaneGroups", "MSysNavPaneGroupToObjects", "MSysNavPaneObjectIDs")
FIREBIRD_SYSTEM_DBS = ("RDB$BACKUP_HISTORY", "RDB$CHARACTER_SETS", "RDB$CHECK_CONSTRAINTS", "RDB$COLLATIONS", "RDB$DATABASE", "RDB$DEPENDENCIES", "RDB$EXCEPTIONS", "RDB$FIELDS", "RDB$FIELD_DIMENSIONS", " RDB$FILES", "RDB$FILTERS", "RDB$FORMATS", "RDB$FUNCTIONS", "RDB$FUNCTION_ARGUMENTS", "RDB$GENERATORS", "RDB$INDEX_SEGMENTS", "RDB$INDICES", "RDB$LOG_FILES", "RDB$PAGES", "RDB$PROCEDURES", "RDB$PROCEDURE_PARAMETERS", "RDB$REF_CONSTRAINTS", "RDB$RELATIONS", "RDB$RELATION_CONSTRAINTS", "RDB$RELATION_FIELDS", "RDB$ROLES", "RDB$SECURITY_CLASSES", "RDB$TRANSACTIONS", "RDB$TRIGGERS", "RDB$TRIGGER_MESSAGES", "RDB$TYPES", "RDB$USER_PRIVILEGES", "RDB$VIEW_RELATIONS")
MAXDB_SYSTEM_DBS = ("SYSINFO", "DOMAIN")
SYBASE_SYSTEM_DBS = ("master", "model", "sybsystemdb", "sybsystemprocs", "tempdb")
DB2_SYSTEM_DBS = ("NULLID", "SQLJ", "SYSCAT", "SYSFUN", "SYSIBM", "SYSIBMADM", "SYSIBMINTERNAL", "SYSIBMTS", "SYSPROC", "SYSPUBLIC", "SYSSTAT", "SYSTOOLS", "SYSDEBUG", "SYSINST")
HSQLDB_SYSTEM_DBS = ("INFORMATION_SCHEMA", "SYSTEM_LOB")
H2_SYSTEM_DBS = ("INFORMATION_SCHEMA",) + ("IGNITE", "ignite-sys-cache")
INFORMIX_SYSTEM_DBS = ("sysmaster", "sysutils", "sysuser", "sysadmin")
MONETDB_SYSTEM_DBS = ("tmp", "json", "profiler")
DERBY_SYSTEM_DBS = ("NULLID", "SQLJ", "SYS", "SYSCAT", "SYSCS_DIAG", "SYSCS_UTIL", "SYSFUN", "SYSIBM", "SYSPROC", "SYSSTAT")
VERTICA_SYSTEM_DBS = ("v_catalog", "v_internal", "v_monitor",)
MCKOI_SYSTEM_DBS = ("",)
PRESTO_SYSTEM_DBS = ("information_schema",)
ALTIBASE_SYSTEM_DBS = ("SYSTEM_",)
MIMERSQL_SYSTEM_DBS = ("information_schema", "SYSTEM",)
CRATEDB_SYSTEM_DBS = ("information_schema", "pg_catalog", "sys")
CLICKHOUSE_SYSTEM_DBS = ("information_schema", "INFORMATION_SCHEMA", "system")
CUBRID_SYSTEM_DBS = ("DBA",)
CACHE_SYSTEM_DBS = ("%Dictionary", "INFORMATION_SCHEMA", "%SYS")
EXTREMEDB_SYSTEM_DBS = ("",)
FRONTBASE_SYSTEM_DBS = ("DEFINITION_SCHEMA", "INFORMATION_SCHEMA")
RAIMA_SYSTEM_DBS = ("",)
VIRTUOSO_SYSTEM_DBS = ("",)
SNOWFLAKE_SYSTEM_DBS = ("INFORMATION_SCHEMA",)
SPANNER_SYSTEM_DBS = ("INFORMATION_SCHEMA", "SPANNER_SYS")

MSSQL_ALIASES = ("microsoft sql server", "mssqlserver", "mssql", "ms")
MYSQL_ALIASES = ("mysql", "my") + ("mariadb", "maria", "memsql", "tidb", "percona", "drizzle", "doris", "starrocks")
PGSQL_ALIASES = ("postgresql", "postgres", "pgsql", "psql", "pg") + ("cockroach", "cockroachdb", "amazon redshift", "redshift", "greenplum", "yellowbrick", "enterprisedb", "yugabyte", "yugabytedb", "opengauss")
ORACLE_ALIASES = ("oracle", "orcl", "ora", "or", "dm8")
SQLITE_ALIASES = ("sqlite", "sqlite3")
ACCESS_ALIASES = ("microsoft access", "msaccess", "access", "jet")
FIREBIRD_ALIASES = ("firebird", "mozilla firebird", "interbase", "ibase", "fb")
MAXDB_ALIASES = ("max", "maxdb", "sap maxdb", "sap db")
SYBASE_ALIASES = ("sybase", "sybase sql server")
DB2_ALIASES = ("db2", "ibm db2", "ibmdb2")
HSQLDB_ALIASES = ("hsql", "hsqldb", "hs", "hypersql")
H2_ALIASES = ("h2",) + ("ignite", "apache ignite")
INFORMIX_ALIASES = ("informix", "ibm informix", "ibminformix")
MONETDB_ALIASES = ("monet", "monetdb",)
DERBY_ALIASES = ("derby", "apache derby",)
VERTICA_ALIASES = ("vertica",)
MCKOI_ALIASES = ("mckoi",)
PRESTO_ALIASES = ("presto",)
ALTIBASE_ALIASES = ("altibase",)
MIMERSQL_ALIASES = ("mimersql", "mimer")
CRATEDB_ALIASES = ("cratedb", "crate")
CUBRID_ALIASES = ("cubrid",)
CLICKHOUSE_ALIASES = ("clickhouse",)
CACHE_ALIASES = ("intersystems cache", "cachedb", "cache", "iris")
EXTREMEDB_ALIASES = ("extremedb", "extreme")
FRONTBASE_ALIASES = ("frontbase",)
RAIMA_ALIASES = ("raima database manager", "raima", "raimadb", "raimadm", "rdm", "rds", "velocis")
VIRTUOSO_ALIASES = ("virtuoso", "openlink virtuoso")
SNOWFLAKE_ALIASES = ("snowflake",)
SPANNER_ALIASES = ("spanner", "google cloud spanner", "google spanner")

DBMS_DIRECTORY_DICT = dict((getattr(DBMS, _), getattr(DBMS_DIRECTORY_NAME, _)) for _ in dir(DBMS) if not _.startswith("_"))

SUPPORTED_DBMS = set(MSSQL_ALIASES + MYSQL_ALIASES + PGSQL_ALIASES + ORACLE_ALIASES + SQLITE_ALIASES + ACCESS_ALIASES + FIREBIRD_ALIASES + MAXDB_ALIASES + SYBASE_ALIASES + DB2_ALIASES + HSQLDB_ALIASES + H2_ALIASES + INFORMIX_ALIASES + MONETDB_ALIASES + DERBY_ALIASES + VERTICA_ALIASES + MCKOI_ALIASES + PRESTO_ALIASES + ALTIBASE_ALIASES + MIMERSQL_ALIASES + CLICKHOUSE_ALIASES + CRATEDB_ALIASES + CUBRID_ALIASES + CACHE_ALIASES + EXTREMEDB_ALIASES + RAIMA_ALIASES + VIRTUOSO_ALIASES + SNOWFLAKE_ALIASES + SPANNER_ALIASES)
SUPPORTED_OS = ("linux", "windows")

DBMS_ALIASES = ((DBMS.MSSQL, MSSQL_ALIASES), (DBMS.MYSQL, MYSQL_ALIASES), (DBMS.PGSQL, PGSQL_ALIASES), (DBMS.ORACLE, ORACLE_ALIASES), (DBMS.SQLITE, SQLITE_ALIASES), (DBMS.ACCESS, ACCESS_ALIASES), (DBMS.FIREBIRD, FIREBIRD_ALIASES), (DBMS.MAXDB, MAXDB_ALIASES), (DBMS.SYBASE, SYBASE_ALIASES), (DBMS.DB2, DB2_ALIASES), (DBMS.HSQLDB, HSQLDB_ALIASES), (DBMS.H2, H2_ALIASES), (DBMS.INFORMIX, INFORMIX_ALIASES), (DBMS.MONETDB, MONETDB_ALIASES), (DBMS.DERBY, DERBY_ALIASES), (DBMS.VERTICA, VERTICA_ALIASES), (DBMS.MCKOI, MCKOI_ALIASES), (DBMS.PRESTO, PRESTO_ALIASES), (DBMS.ALTIBASE, ALTIBASE_ALIASES), (DBMS.MIMERSQL, MIMERSQL_ALIASES), (DBMS.CLICKHOUSE, CLICKHOUSE_ALIASES), (DBMS.CRATEDB, CRATEDB_ALIASES), (DBMS.CUBRID, CUBRID_ALIASES), (DBMS.CACHE, CACHE_ALIASES), (DBMS.EXTREMEDB, EXTREMEDB_ALIASES), (DBMS.FRONTBASE, FRONTBASE_ALIASES), (DBMS.RAIMA, RAIMA_ALIASES), (DBMS.VIRTUOSO, VIRTUOSO_ALIASES), (DBMS.SNOWFLAKE, SNOWFLAKE_ALIASES), (DBMS.SPANNER, SPANNER_ALIASES))

USER_AGENT_ALIASES = ("ua", "useragent", "user-agent")
REFERER_ALIASES = ("ref", "referer", "referrer")
HOST_ALIASES = ("host",)

UPPER_CASE_DBMSES = set((DBMS.ORACLE, DBMS.DB2, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.H2, DBMS.HSQLDB, DBMS.DERBY, DBMS.ALTIBASE, DBMS.SNOWFLAKE))

H2_DEFAULT_SCHEMA = HSQLDB_DEFAULT_SCHEMA = "PUBLIC"
VERTICA_DEFAULT_SCHEMA = "public"
MCKOI_DEFAULT_SCHEMA = "APP"
CACHE_DEFAULT_SCHEMA = "SQLUser"
SPANNER_DEFAULT_SCHEMA = "default"

PLUS_ONE_DBMSES = set((DBMS.ORACLE, DBMS.DB2, DBMS.ALTIBASE, DBMS.MSSQL, DBMS.CACHE))

WINDOWS_RESERVED_NAMES = ("CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9")

BASIC_HELP_ITEMS = (
    "url",
    "googleDork",
    "data",
    "cookie",
    "randomAgent",
    "proxy",
    "testParameter",
    "dbms",
    "level",
    "risk",
    "technique",
    "getAll",
    "getBanner",
    "getCurrentUser",
    "getCurrentDb",
    "getPasswordHashes",
    "getDbs",
    "getTables",
    "getColumns",
    "getSchema",
    "dumpTable",
    "dumpAll",
    "db",
    "tbl",
    "col",
    "osShell",
    "osPwn",
    "batch",
    "checkTor",
    "flushSession",
    "tor",
    "sqlmapShell",
    "wizard",
)

SHELL_WRITABLE_DIR_TAG = "%WRITABLE_DIR%"
SHELL_RUNCMD_EXE_TAG = "%RUNCMD_EXE%"

NULL = "NULL"

BLANK = "<blank>"

CURRENT_DB = "CD"

CURRENT_USER = "CU"

SESSION_SQLITE_FILE = "session.sqlite"

FILE_PATH_REGEXES = (r"<b>(?P<result>[^<>]+?)</b> on line \d+", r"\bin (?P<result>[^<>'\"]+?)['\"]? on line \d+", r"(?:[>(\[\s])(?P<result>[A-Za-z]:[\\/][\w. \\/-]*)", r"(?:[>(\[\s])(?P<result>/\w[/\w.~-]+)", r"\bhref=['\"]file://(?P<result>/[^'\"]+)", r"\bin <b>(?P<result>[^<]+): line \d+")

ERROR_PARSING_REGEXES = (
    r"\[Microsoft\]\[ODBC SQL Server Driver\]\[SQL Server\](?P<result>[^<]+)",
    r"<b>[^<]{0,100}(fatal|error|warning|exception)[^<]*</b>:?\s*(?P<result>[^<]+)",
    r"(?m)^\s{0,100}(fatal|error|warning|exception):?\s*(?P<result>[^\n]+?)$",
    r"(sql|dbc)[^>'\"]{0,32}(fatal|error|warning|exception)(</b>)?:\s*(?P<result>[^<>]+)",
    r"(?P<result>[^\n>]{0,100}SQL Syntax[^\n<]+)",
    r"(?s)<li>Error Type:<br>(?P<result>.+?)</li>",
    r"CDbCommand (?P<result>[^<>\n]*SQL[^<>\n]+)",
    r"Code: \d+. DB::Exception: (?P<result>[^<>\n]*)",
    r"error '[0-9a-f]{8}'((<[^>]+>)|\s)+(?P<result>[^<>]+)",
    r"\[[^\n\]]{1,100}(ODBC|JDBC)[^\n\]]+\](\[[^\]]+\])?(?P<result>[^\n]+(in query expression|\(SQL| at /[^ ]+pdo)[^\n<]+)",
    r"(?P<result>query error: SELECT[^<>]+)",
    r"(?P<result>(?:(?:ORA|PLS)-[0-9]{5}:|SQLCODE[ =:]+-?[0-9]+|SQLSTATE[ =:]+[0-9A-Z]{5}|Dynamic SQL Error|DB2 SQL error:|SAP DBTech JDBC:|SQLiteException:|You have an error in your SQL syntax;|Incorrect syntax near |Unclosed quotation mark after the character string|near \"[^\"]+\": syntax error)[^\n<]*)"
)

META_CHARSET_REGEX = r'(?si)<head>.*<meta[^>]+charset="?(?P<result>[^"> ]+).*</head>'

META_REFRESH_REGEX = r'(?i)<meta http-equiv="?refresh"?[^>]+content="?[^">]+;\s*(url=)?["\']?(?P<result>[^\'">]+)'

JAVASCRIPT_HREF_REGEX = r'<script>\s*(\w+\.)?location\.href\s*=\s*["\'](?P<result>[^"\']+)'

EMPTY_FORM_FIELDS_REGEX = r'(&|\A)(?P<result>[^=]+=)(?=&|\Z)'

COMMON_PASSWORD_SUFFIXES = ("1", "123", "2", "12", "3", "13", "7", "11", "5", "22", "23", "01", "4", "07", "21", "14", "10", "06", "08", "8", "15", "69", "16", "6", "18")

COMMON_PASSWORD_SUFFIXES += ("!", ".", "*", "!!", "?", ";", "..", "!!!", ",", "@")

WEBSCARAB_SPLITTER = "### Conversation"

BURP_REQUEST_REGEX = r"={10,}\s+([A-Z]{3,} .+?)\s+(={10,}|\Z)"

BURP_XML_HISTORY_REGEX = r'<port>(\d+)</port>.*?<request base64="true"><!\[CDATA\[([^]]+)'

UNICODE_ENCODING = "utf8"

URI_HTTP_HEADER = "URI"

URI_INJECTABLE_REGEX = r"//[^/]*/([^\.*?]+)\Z"

SENSITIVE_DATA_REGEX = r"(\s|=)(?P<result>[^\s=]*\b%s\b[^\s]*)\s"

SENSITIVE_OPTIONS = ("hostname", "answers", "data", "dnsDomain", "googleDork", "authCred", "proxyCred", "tbl", "db", "col", "user", "cookie", "proxy", "fileRead", "fileWrite", "fileDest", "testParameter", "authCred", "sqlQuery", "requestFile", "csrfToken", "csrfData", "csrfUrl", "testParameter")

MAX_NUMBER_OF_THREADS = 10

MIN_STATISTICAL_RANGE = 0.01

MIN_RATIO = 0.0

MAX_RATIO = 1.0

CANDIDATE_SENTENCE_MIN_LENGTH = 10

CUSTOM_INJECTION_MARK_CHAR = '*'

IGNORE_CODE_WILDCARD = '*'

INJECT_HERE_REGEX = r"(?i)%INJECT[_ ]?HERE%"

MIN_ERROR_CHUNK_LENGTH = 8

MAX_ERROR_CHUNK_LENGTH = 1024

EXCLUDE_UNESCAPE = ("WAITFOR DELAY '", " INTO DUMPFILE ", " INTO OUTFILE ", "CREATE ", "BULK ", "EXEC ", "RECONFIGURE ", "DECLARE ", "'%s'" % CHAR_INFERENCE_MARK)

REFLECTED_VALUE_MARKER = "__REFLECTED_VALUE__"

REFLECTED_BORDER_REGEX = r"[^A-Za-z]+"

REFLECTED_REPLACEMENT_REGEX = r"[^\n]{1,168}"

REFLECTED_REPLACEMENT_TIMEOUT = 3

REFLECTED_MAX_REGEX_PARTS = 10

URLENCODE_FAILSAFE_CHARS = "()|,"

YUGE_FACTOR = 1000

URLENCODE_CHAR_LIMIT = 2000

DEFAULT_MSSQL_SCHEMA = "dbo"

HASH_MOD_ITEM_DISPLAY = 11

HASH_EMPTY_PASSWORD_MARKER = "<empty>"

MAX_INT = sys.maxsize

UNSAFE_DUMP_FILEPATH_REPLACEMENT = '_'

RESTORE_MERGED_OPTIONS = ("col", "db", "dbms", "os", "dnsDomain", "privEsc", "tbl", "regexp", "string", "textOnly", "threads", "timeSec", "tmpPath", "uChar", "user")

IGNORE_PARAMETERS = ("__VIEWSTATE", "__VIEWSTATEENCRYPTED", "__VIEWSTATEGENERATOR", "__EVENTARGUMENT", "__EVENTTARGET", "__EVENTVALIDATION", "ASPSESSIONID", "ASP.NET_SESSIONID", "JSESSIONID", "CFID", "CFTOKEN")

ASP_NET_CONTROL_REGEX = r"(?i)\Actl\d+\$"

GOOGLE_ANALYTICS_COOKIE_REGEX = r"(?i)\A(_ga|_gid|_gat|_gcl_au|__utm[abcz])"

SQLMAP_ENVIRONMENT_PREFIX = "SQLMAP_"

PROXY_ENVIRONMENT_VARIABLES = ("all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY")

TURN_OFF_RESUME_INFO_LIMIT = 20

RESULTS_FILE_FORMAT = "results-%m%d%Y_%I%M%p.csv"

CODECS_LIST_PAGE = "http://docs.python.org/library/codecs.html#standard-encodings"

SQL_SCALAR_REGEX = r"\A(SELECT(?!\s+DISTINCT\(?))?\s*\w*\("

IGNORE_SAVE_OPTIONS = ("saveConfig",)

LOCALHOST = "127.0.0.1"

DEFAULT_TOR_SOCKS_PORTS = (9050, 9150)

DEFAULT_TOR_HTTP_PORTS = (8123, 8118)

LOW_TEXT_PERCENT = 20

VERSION_COMPARISON_CORRECTION = 0.0001

IGNORE_SPACE_AFFECTED_KEYWORDS = ("CAST", "COUNT", "EXTRACT", "GROUP_CONCAT", "MAX", "MID", "MIN", "SESSION_USER", "SUBSTR", "SUBSTRING", "SUM", "SYSTEM_USER", "TRIM")

GET_VALUE_UPPERCASE_KEYWORDS = ("SELECT", "FROM", "WHERE", "DISTINCT", "COUNT")

LEGAL_DISCLAIMER = "Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program"

REFLECTIVE_MISS_THRESHOLD = 20

HTML_TITLE_REGEX = r"(?i)<title>(?P<result>[^<]+)</title>"

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

IGNORED_OPTIONS = ("--compressed",)

DUMMY_SQL_INJECTION_CHARS = ";()'"

DUMMY_USER_INJECTION = r"(?i)[^\w](AND|OR)\s+[^\s]+[=><]|\bUNION\b.+\bSELECT\b|\bSELECT\b.+\bFROM\b|\b(CONCAT|information_schema|SLEEP|DELAY|FLOOR\(RAND)\b"

CRAWL_EXCLUDE_EXTENSIONS = frozenset(("3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "accdb", "access", "adp", "ai", "aif", "aiff", "apk", "ar", "asf", "au", "avi", "bak", "bin", "bin", "bk", "bkp", "bmp", "btif", "bz2", "c", "cab", "caf", "cfg", "cgm", "cmx", "com", "conf", "config", "cpio", "cpp", "cr2", "cue", "dat", "db", "dbf", "deb", "debug", "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "dylib", "ear", "ecelp4800", "ecelp7470", "ecelp9600", "egg", "elf", "env", "eol", "eot", "epub", "error", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", "fvt", "g3", "gif", "go", "gz", "h", "h261", "h263", "h264", "ico", "ief", "img", "ini", "ipa", "iso", "jar", "java", "jpeg", "jpg", "jpgv", "jpm", "js", "jxr", "ktx", "lock", "log", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdb", "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "msi", "mxu", "nef", "npx", "nrg", "o", "oga", "ogg", "ogv", "old", "otf", "ova", "ovf", "pbm", "pcx", "pdf", "pea", "pgm", "php", "pic", "pid", "pkg", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "py", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rb", "rgb", "rip", "rlc", "rs", "run", "rz", "s3m", "s7z", "scm", "scpt", "service", "sgi", "shar", "sil", "smv", "so", "sock", "socket", "sqlite", "sqlitedb", "sub", "svc", "swf", "swo", "swp", "sys", "tar", "tbz2", "temp", "tga", "tgz", "tif", "tiff", "tlz", "tmp", "toast", "torrent", "ts", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "vbox", "vdi", "vhd", "vhdx", "viv", "vmdk", "vmx", "vob", "vxd", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "yaml", "yml", "z", "zip", "zipx"))

PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;']+)|(\*/\*)"

BRUTE_TABLE_EXISTS_TEMPLATE = "EXISTS(SELECT %d FROM %s)"

BRUTE_COLUMN_EXISTS_TEMPLATE = "EXISTS(SELECT %s FROM %s)"

SHELLCODEEXEC_RANDOM_STRING_MARKER = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

LAST_UPDATE_NAGGING_DAYS = 180

MIN_ERROR_PARSING_NON_WRITING_RATIO = 0.05

CHECK_INTERNET_ADDRESS = "http://www.google.com/generate_204"

CHECK_INTERNET_CODE = 204

IPS_WAF_CHECK_PAYLOAD = "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"

WAF_ATTACK_VECTORS = (
    "",  # NIL
    "search=<script>alert(1)</script>",
    "file=../../../../etc/passwd",
    "q=<invalid>foobar",
    "id=1 %s" % IPS_WAF_CHECK_PAYLOAD
)

ROTATING_CHARS = ('\\', '|', '|', '/', '-')

BIGARRAY_CHUNK_SIZE = 32 * 1024 * 1024

BIGARRAY_COMPRESS_LEVEL = 4

SOCKET_PRE_CONNECT_QUEUE_SIZE = 3

TRIM_STDOUT_DUMP_SIZE = 256

DUMP_FILE_BUFFER_SIZE = 1024

PARSE_HEADERS_LIMIT = 3

ORDER_BY_STEP = 10

ORDER_BY_MAX = 1000

MAX_REVALIDATION_STEPS = 5

PARAMETER_SPLITTING_REGEX = r"[,|;]"

UNENCODED_ORIGINAL_VALUE = "original"

COMMON_USER_COLUMNS = frozenset(("login", "user", "uname", "username", "user_name", "user_login", "account", "account_name", "auth_user", "benutzername", "benutzer", "utilisateur", "usager", "consommateur", "utente", "utilizzatore", "utilizator", "utilizador", "usufrutuario", "korisnik", "uporabnik", "usuario", "consumidor", "client", "customer", "cuser"))

DEFAULT_GET_POST_DELIMITER = '&'

DEFAULT_COOKIE_DELIMITER = ';'

FORCE_COOKIE_EXPIRATION_TIME = "9999999999"

GITHUB_REPORT_PAT_TOKEN = ""

HASHDB_FLUSH_THRESHOLD_ITEMS = 200

HASHDB_FLUSH_THRESHOLD_TIME = 5

HASHDB_FLUSH_RETRIES = 3

HASHDB_RETRIEVE_RETRIES = 3

HASHDB_END_TRANSACTION_RETRIES = 3

HASHDB_MILESTONE_VALUE = "GpqxbkWTfz"  # python -c 'import random, string; print "".join(random.sample(string.ascii_letters, 10))'

PICKLE_PROTOCOL = 2

LARGE_OUTPUT_THRESHOLD = 1024 ** 2

SLOW_ORDER_COUNT_THRESHOLD = 10000

HASH_RECOGNITION_QUIT_THRESHOLD = 1000

HASH_BINARY_COLUMNS_REGEX = r"(?i)pass|psw|hash"

MAX_SINGLE_URL_REDIRECTIONS = 4

MAX_TOTAL_REDIRECTIONS = 10

MAX_STABILITY_DELAY = 0.5

MAX_DNS_LABEL = 63

DNS_BOUNDARIES_ALPHABET = re.sub(r"[a-fA-F]", "", string.ascii_letters)

HEURISTIC_CHECK_ALPHABET = ('"', '\'', ')', '(', ',', '.')

BANNER = re.sub(r"\[.\]", lambda _: "[\033[01;41m%s\033[01;49m]" % random.sample(HEURISTIC_CHECK_ALPHABET, 1)[0], BANNER)

DUMMY_NON_SQLI_CHECK_APPENDIX = "<'\">"

FI_ERROR_REGEX = r"(?i)[^\n]{0,100}(no such file|failed (to )?open)[^\n]{0,100}"

NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH = 6

MAX_CONNECTION_READ_SIZE = 10 * 1024 * 1024

MAX_CONNECTION_TOTAL_SIZE = 100 * 1024 * 1024

MAX_DIFFLIB_SEQUENCE_LENGTH = 10 * 1024 * 1024

HEURISTIC_PAGE_SIZE_THRESHOLD = 64 * 1024

MAX_BISECTION_LENGTH = 50 * 1024 * 1024

LARGE_READ_TRIM_MARKER = "__TRIMMED_CONTENT__"

GENERIC_SQL_COMMENT = "-- [RANDSTR]"

VALID_TIME_CHARS_RUN_THRESHOLD = 100

CHECK_ZERO_COLUMNS_THRESHOLD = 10

CHECK_SQLITE_TYPE_THRESHOLD = 100

BOLD_PATTERNS = ("' injectable", "provided empty", "leftover chars", "might be injectable", "' is vulnerable", "is not injectable", "does not seem to be", "test failed", "test passed", "live test final result", "test shows that", "the back-end DBMS is", "created Github", "blocked by the target server", "protection is involved", "CAPTCHA", "specific response", "NULL connection is supported", "PASSED", "FAILED", "for more than", "connection to ", "will be trimmed", "counterpart to database")

BOLD_PATTERNS_REGEX = '|'.join(BOLD_PATTERNS)

RANDOMIZATION_TLDS = ("com", "net", "ru", "org", "de", "uk", "br", "jp", "cn", "fr", "it", "pl", "tv", "edu", "in", "ir", "es", "me", "info", "gr", "gov", "ca", "co", "se", "cz", "to", "vn", "nl", "cc", "az", "hu", "ua", "be", "no", "biz", "io", "ch", "ro", "sk", "eu", "us", "tw", "pt", "fi", "at", "lt", "kz", "cl", "hr", "pk", "lv", "la", "pe", "au")

GENERIC_DOC_ROOT_DIRECTORY_NAMES = ("htdocs", "httpdocs", "public", "public_html", "wwwroot", "www", "site")

MAX_HELP_OPTION_LENGTH = 18

MAX_CONNECT_RETRIES = 100

FORMAT_EXCEPTION_STRINGS = ("Type mismatch", "Error converting", "Please enter a", "Conversion failed", "String or binary data would be truncated", "Failed to convert", "unable to interpret text value", "Input string was not in a correct format", "System.FormatException", "java.lang.NumberFormatException", "ValueError: invalid literal", "TypeMismatchException", "CF_SQL_INTEGER", "CF_SQL_NUMERIC", " for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException", "Invalid parameter type", "Attribute validation error for tag", "is not of type numeric", "<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type", "invalid number", "character to number conversion error", "unable to interpret text value", "String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ", "InvalidDataException", "Arguments are of the wrong type", "Invalid conversion")

VIEWSTATE_REGEX = r'(?i)(?P<name>__VIEWSTATE[^"]*)[^>]+value="(?P<result>[^"]+)'

EVENTVALIDATION_REGEX = r'(?i)(?P<name>__EVENTVALIDATION[^"]*)[^>]+value="(?P<result>[^"]+)'

LIMITED_ROWS_TEST_NUMBER = 15

RESTAPI_DEFAULT_ADAPTER = "wsgiref"

RESTAPI_DEFAULT_ADDRESS = "127.0.0.1"

RESTAPI_DEFAULT_PORT = 8775

RESTAPI_UNSUPPORTED_OPTIONS = ("sqlShell", "wizard", "evalCode", "alert")

INVALID_UNICODE_PRIVATE_AREA = False

INVALID_UNICODE_CHAR_FORMAT = r"\x%02x"

MIN_HTTPX_VERSION = "0.28"

XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null|\[).*\}\s*(\]\s*)*\Z'

JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*('[^']+'|\"[^\"]+\"|\w+)\s*:\s*('[^']+'|\"[^\"]+\"|\d+).*\}\s*(\]\s*)*\Z"

MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="

ARRAY_LIKE_RECOGNITION_REGEX = r"(\A|%s)(\w+)\[\d*\]=.+%s\2\[\d*\]=" % (DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER)

DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"

PLAIN_TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"

SUHOSIN_MAX_VALUE_LENGTH = 512

MIN_BINARY_DISK_DUMP_SIZE = 100

PAYLOAD_XML_FILES = ("boolean_blind.xml", "error_based.xml", "inline_query.xml", "stacked_queries.xml", "time_blind.xml", "union_query.xml")

FORM_SEARCH_REGEX = r"(?si)<form(?!.+<form).+?</form>"

MAX_HISTORY_LENGTH = 1000

MIN_ENCODED_LEN_CHECK = 5

METASPLOIT_SESSION_TIMEOUT = 180

LOBLKSIZE = 2048

EVALCODE_ENCODED_PREFIX = "EVAL_"

ZIP_HEADER = b"\x50\x4b\x03\x04"

NETSCAPE_FORMAT_HEADER_COOKIES = "# Netscape HTTP Cookie File."

CSRF_TOKEN_PARAMETER_INFIXES = ("csrf", "xsrf", "token", "nonce")

BRUTE_DOC_ROOT_PREFIXES = {
    OS.LINUX: ("/var/www", "/usr/local/apache", "/usr/local/apache2", "/usr/local/www/apache22", "/usr/local/www/apache24", "/usr/local/httpd", "/var/www/nginx-default", "/srv/www", "/var/www/%TARGET%", "/var/www/vhosts/%TARGET%", "/var/www/virtual/%TARGET%", "/var/www/clients/vhosts/%TARGET%", "/var/www/clients/virtual/%TARGET%", "/Library/WebServer/Documents", "/opt/homebrew/var/www"),
    OS.WINDOWS: ("/xampp", "/Program Files/xampp", "/wamp", "/Program Files/wampp", "/Apache/Apache", "/apache", "/Program Files/Apache Group/Apache", "/Program Files/Apache Group/Apache2", "/Program Files/Apache Group/Apache2.2", "/Program Files/Apache Group/Apache2.4", "/Inetpub/wwwroot", "/Inetpub/wwwroot/%TARGET%", "/Inetpub/vhosts/%TARGET%")
}

BRUTE_DOC_ROOT_SUFFIXES = ("", "html", "htdocs", "httpdocs", "php", "public", "src", "site", "build", "web", "www", "data", "sites/all", "www/build")

BRUTE_DOC_ROOT_TARGET_MARK = "%TARGET%"

KB_CHARS_BOUNDARY_CHAR = 'q'

KB_CHARS_LOW_FREQUENCY_ALPHABET = "zqxjkvbp"

PRINTABLE_BYTES = set(bytes(string.printable, "ascii") if six.PY3 else string.printable)

HTTP_CHUNKED_SPLIT_KEYWORDS = ("SELECT", "UPDATE", "INSERT", "FROM", "LOAD_FILE", "UNION", "information_schema", "sysdatabases", "msysaccessobjects", "msysqueries", "sysmodules")

HTML_DUMP_CSS_STYLE = """<style>
table{
    margin:10;
    background-color:#FFFFFF;
    font-family:verdana;
    font-size:12px;
    align:center;
}
thead{
    font-weight:bold;
    background-color:#4F81BD;
    color:#FFFFFF;
}
tr:nth-child(even) {
    background-color: #D3DFEE
}
td{
    font-size:12px;
}
th{
    font-size:12px;
    cursor:pointer;
}
</style>"""

for key, value in os.environ.items():
    if key.upper().startswith("%s_" % SQLMAP_ENVIRONMENT_PREFIX):
        _ = key[len(SQLMAP_ENVIRONMENT_PREFIX) + 1:].upper()
        if _ in globals():
            original = globals()[_]
            if isinstance(original, int):
                try:
                    globals()[_] = int(value)
                except ValueError:
                    pass
            elif isinstance(original, bool):
                globals()[_] = value.lower() in ('1', 'true')
            elif isinstance(original, (list, tuple)):
                globals()[_] = [__.strip() for __ in _.split(',')]
            else:
                globals()[_] = value
