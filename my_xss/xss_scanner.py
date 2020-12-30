import optparse, random, re, string, urllib, urllib.parse, urllib.request
import logging
import argparse
import requests
from requests import session

SMALLER_CHAR_POOL = ('<', '>')       #参数值篡改                                                    
LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')          
GET, POST = "GET", "POST"  
PREFIX_SUFFIX_LENGTH = 5                                                                    
COOKIE = "Cookie"                                   
TIMEOUT = 30                                                                                
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  
REGULAR_PATTERNS = (
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'"),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"'),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)#平常的xss模式；似乎直接就能在url中发现
REGULAR_PATTERNS_CONTENTS = {
    '.xss.':{'un_filtering':'尖括号<>', 'payload_name':'纯字符','remove':'无','method':'使用标签即可'},
    '>.xss.<':{'un_filtering':'尖括号<>', 'payload_name':'在标签外','remove':'>.xss<','method':'使用标签。删除响应中的script标签和注释，防止payload测试与No.5&2重合'},
    '<.xss.>':{'un_filtering':'无', 'payload_name':'在标签内','remove':'<script..</script>和注释和=\'...\'和\"...\"','method':'可以通过输入\\>来逃避'},
    '<.\".xss.\".>':{'un_filtering':'双引号\"', 'payload_name':'在标签内，被双引号包裹','remove':'<script..</script>和注释和=\\','method':'逃逸双引号，利用标签的属性，删除响应中的script标签、注释、\\，可以通过输入\">来逃避'},
    '<.\'.xss.\'.>':{'un_filtering':'单引号\'', 'payload_name':'在标签内，被单引号包裹','remove':'<script..</script>和注释和=\\','method':'逃逸单引号，利用标签的属性，删除响应中的script标签、注释、\\，可以通过输入\'>来逃避'},
    '<script>.xss.</script>':{'un_filtering':'分号;', 'payload_name':'在<script>标签内','remove':'无','method':'使用;终端语句后自定义js代码'},
    '<script>.\".xss.\".</script>':{'un_filtering':'双引号\"和分号;', 'payload_name':'在<script>标签内，被双引号包裹','remove':'\"','method':'先逃逸双引号，然后使用;终端语句后自定义js代码。删除响应中的\"'},
    '<script>.\'.xss.\'.</script>':{'un_filtering':'单引号\"和分号;', 'payload_name':'在<script>标签内','remove':'\'','method':'先逃逸单引号，然后使用;终端语句后自定义js代码。删除响应中的\''},
    '<!--.xss.-->':{'un_filtering':'尖括号<>', 'payload_name':'在注释内','remove':'无','method':'闭合注释后使用标签'}
}#上面正则表达式的“人话版”

_headers = {}     # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    try:
        req = urllib.request.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))), data.encode("utf8", "ignore") if data else None, _headers)
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    return (retval.decode("utf8", "ignore") if hasattr(retval, "decode") else "") or ""

def _contains(content, chars):
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
    return all(char in content for char in chars)   # all 函数用来判断给定的可迭代参数 iterable 中的所有元素是否都为 TRUE

def scan_page(url, data=None):
    retval, usable = False, False
    # 如果url有值的话
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data # \Z 代表输入的结尾位置，但是字符串的结尾可以有也可以没有终止子（final terminator：\n, \r, \r\n, \u0085, \u2028, \u2029）

    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")#如果data是None就返回"" #当前待处理
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):#finditer找出匹配的子串并以迭代器的形式返回；之后match中找到parameter之后，似乎会依次返回
                #键=值的形式
                found, usable = False, True
                print(" * scanning %s parameter '%s'\n" % (phase, match.group("parameter")))# ?P<parameter>似乎就是再赋予键key
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in range(2)) #从string.xxx中选取LENGTH长度的东西
                #随机前后缀
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found:
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix))))#仍然是转化
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)# 再把prefix换回去回去
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):
                                        print(" ** %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        pos = info.find(',')
                                        print("\n *** regex:\t\t\t\t\t\t%s" %info[1:pos-1])
                                        print(" *** 要想payload有效,则不能过滤:\t\t\t%s" %REGULAR_PATTERNS_CONTENTS[info[1:pos-1]]['un_filtering'])
                                        print(" *** payload名:\t\t\t\t\t\t%s" %REGULAR_PATTERNS_CONTENTS[info[1:pos-1]]['payload_name'])
                                        print(" *** 为了防止与其他payload重合，响应中需要去除的内容:\t%s" %REGULAR_PATTERNS_CONTENTS[info[1:pos-1]]['remove'])
                                        print(" *** 利用方式:\t\t\t\t\t\t%s" %REGULAR_PATTERNS_CONTENTS[info[1:pos-1]]['method'])
                                        found = retval = True
                                    break
        if not usable:#没有找到参数
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval

parser = optparse.OptionParser()
parser.add_option("-u", "--url", dest="url", help="Target URL")
parser.add_option("--d", "--data", dest="data", help="POST data")
parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
parser.print_help()
print("Click Ctrl-C to exit.")
try:
    while(True):
        options,args = parser.parse_args()
        _ = input("\n请输入:")
        if _ not in '-h' and _ not in '--version':
            args_list=_.split(" ")
            options,args = parser.parse_args(args_list)#解析成字典放入options中；
        elif _ in '-h':
            parser.print_help()
            continue
        if options.url:
            #_ = dict(session='security=low; JSESSIONID=F3A759611FA73D8DA307756147AFCC63; acopendivids=swingset,jotto,phpbb2,redmine; acgroupswithpersist=nada; PHPSESSID=raiip1caq0f5ql9qllcvkirrk6')#; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')#PHPSESSID='bhvb21iekc4s0p6pnbqp6e4na3)#session='.eJwlzztuAzEMBNC7qHYhkqJE-ShpFhI_sRHEAXbtwghyd8tIOcUbzPymLXY_Lul83x9-StvV0jmJCHbKDaX0EGQqNrtMHRWEwdog54iYswJOrqhos6k7CVkrXXsTf1vWRjXDqhBuUIIXKaAx3NSsjzZJVk0lgOxuWUvtVFpJp6THHtv958tvaw9WjhyTLYcQY_ZsoiTVqUAdYCLaCyEud_0en77Ix-X2nCs_Dt__T2EGQaCWIf29AN5YRR8.XefB7g.1a_c6rOf5YGWBNACqrwxvDT9i9U; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')#PHPSESSID='p3d8eh46u7gu6ob57tdvpjkir0')#session='.eJwlzztuAzEMBNC7qHYhkqJE-ShpFhI_sRHEAXbtwghyd8tIOcUbzPymLXY_Lul83x9-StvV0jmJCHbKDaX0EGQqNrtMHRWEwdog54iYswJOrqhos6k7CVkrXXsTf1vWRjXDqhBuUIIXKaAx3NSsjzZJVk0lgOxuWUvtVFpJp6THHtv958tvaw9WjhyTLYcQY_ZsoiTVqUAdYCLaCyEud_0en77Ix-X2nCs_Dt__T2EGQaCWIf29AN5YRR8.XefB7g.1a_c6rOf5YGWBNACqrwxvDT9i9U; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')####cookie必须是字典形式！None#
            #cookies = requests.utils.cookiejar_from_dict(_)
            #options.cookies=cookies
            #session.cookies=cookies
            result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)# 判断是否有http;若没有则自行增加
            print("\nresults: %s vulnerabilities found" % ("possible" if result else "no"))
        else:
            parser.print_help()
except KeyboardInterrupt:
    print("\r (x) Ctrl-C pressed")


#测试网址1： -u http://testphp.vulnweb.com/search.php --d searchFor=zzz
#测试网址2：
#-u http://leettime.net/xsslab1/chalg1.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/sta_ge2.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/stg_3.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/chlng_004.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/chl05.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/ch__006_.php?name=1&submit=Search
#-u http://leettime.net/xsslab1/ch_7_stage.php?name=1&submit=Search

#测试网址3：
#-u https://xss-quiz.int21h.jp/?sid=1

