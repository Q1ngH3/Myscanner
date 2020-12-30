import requests
import re
import queue
from lxml import etree
import lxml.html
import random
from urllib.parse import urljoin
from fake_useragent import UserAgent
import json
import logging
import colorlog
import concurrent.futures
import argparses
import datetime
import os
from threading import Lock
from requests.adapters import HTTPAdapter
import multiprocessing
from test import mysql
'''
删掉的一些代码，可能之后还会用到
            if next_url.startswith("javascript:"):
                logger.warning("a javascript function",next_url)#print("a javascript function",next_url)
                continue
            if next_url not in total_seen.keys() :
                if next_url.endswith(".html"):
                    logger.warning("only returns a html",next_url)#print("only returns a html",next_url)
                    continue
                try:
                    session.headers.update({'User-Agent':get_random_ua()})
                    
                    #应该都是从current_url生成的url
                    r = session.get(url=next_url,proxies=get_random_proxies())
                    if r.status_code<300:
                        if r.headers.get('content-type')!='text/html':#可能其中还有些纰漏（比如，不是反向直接排除而是正向排除）
                            logger.info("valid url - >",next_url)#print("valid url - >",next_url)

                            total_seen[next_url] = r #seen.add(next_url)#这个已经遍历过的网站了
                            #每次找到新网站，都知道他已经看过了// 并且它将作为新的深挖对象
                            #另外，如果是已经看过的网站，则已经没有必要再次深挖
                            url_queue.append(next_url)#需要继续深挖的网站
                        else:
                            logger.debug("valide response but not refer to html - >",next_url)#print("valide response but not refer to html - >",next_url)
                    else:
                        logger.warning("invalid response - > ",next_url)#print("invalid response - > ",next_url)
                except Exception as e:
                    logger.critical("unknown error - > ",next_url,e)#print("unknown error - > ",next_url,e)
                    continue


                            if __name__ == '__main__':
            multiprocessing.freeze_support()
            with concurrent.futures.ProcessPoolExecutor() as executor:#进程池
                for next_url, response in zip(urls, executor.map(valid_url, urls, chunksize=5)):
                    if response:
                        url_queue.append(next_url)
                        total_seen[next_url] = response

'''
#auth = HTTPBasicAuth('fake@example.com', 'not_a_real_password')??

logger = colorlog.getLogger("scanner_scraper")#这个name实际上是层级化的，如果使用__name__那么，似乎和python包的结构一样
LOG_FORMAT_CONSOLE = "%(log_color)s%(asctime)s [%(levelname)-5.5s] %(message)s"
logging.root.setLevel(logging.DEBUG)
formatter_console = colorlog.ColoredFormatter(
#	LOG_FORMAT_CONSOLE,
	datefmt=None,
	reset=True,
	log_colors={
		'DEBUG':    'cyan',
		'INFO':     'green',
		'WARNING':  'bold_yellow',
		'ERROR':    'bold_red',
		'CRITICAL': 'bold_red,bg_white',
	},
	secondary_log_colors={},
	style='%'
)

#logging.basicConfig(datefmt='[%m/%d/%Y-%H:%M:%S]')

handler = colorlog.StreamHandler()
handler.setLevel(logging.NOTSET)
handler.setFormatter(formatter_console)
logger.addHandler(handler)

'''
coloredlogs.install(
    logger=logger,#只选择从本文件以及本库中传出的log，将库中的忽略
    fmt='%(asctime)s %(levelname)s - %(message)s',#自定义输出格式
    level=logging.INFO
)
 '''

def scrape(root_url):
    url_queue = []#列表当成队列用呗
    #seen = set()#定义已经获得的url集合
    #total_seen = {}
    #seen.add(root_url)invalid
    url_queue.append(root_url)#append直接放在队尾
    #这一步是以防利用没有cookie的请求导致直接跳回到主页面而进行的操作；
    m = None
    if url.startswith("https"):
        _ = re.search('https://[^//]*', root_url).group()#匹配http://直到第一个/
    elif url.startswith("http"):#总之是显式地匹配了，但是如果这两步都没匹配成功的话是不是也就差不多了
        _ = re.search('http://[^//]*', root_url).group()#匹配https://直到第一个/
    else:
        print("your url should startwith http or https :)")
        return
    #当个大善人可以给他加个http，但考虑到我们的使用者起码应该有点脑子，所以就算了
    #如果不加.group()的话那么只能返回一个match类
    if _ and _ != root_url:
        #seen.add(_)
        url_queue.append(_)
    
    for sequence in range(len(url_queue)):
        try:
            session.headers.update({'User-Agent':get_random_ua()})
            session.headers.update({'referer': url_queue[sequence]})
            res = session.get(url=url_queue[sequence],timeout=(5, 10),proxies=get_random_proxies())
            #if res.status_code>=300:
            res.raise_for_status()
            #url_queue.pop(sequence)           
            if res.cookies:
                session.cookies = res.cookies
                #session.cookies.update(res.cookies)
            total_seen[url_queue[sequence]] = res #创建键值对字典

        except requests.exceptions.ConnectionError as e:
            logger.critical("Connection Error - > %s with exception %s\n",url_queue[sequence],e)
            #url_queue.pop(sequence)
        except requests.exceptions.HTTPError as e:
            logger.warning("bad status code - > %s with exception %s\n",url_queue[sequence],e)
            #url_queue.pop(sequence)
        except requests.exceptions.TooManyRedirects as e:
            logger.error("Too many redirects - > %s with exception %s\n",url_queue[sequence],e)
            #url_queue.pop(sequence)
#        except Exception as e:
#            logger.critical("unkown error - > %s with exception %s\n",url_queue[sequence],e)#print("unkown error - > ",base_url,e)
            #url_queue.pop(sequence)

    ##########如果第一个url不可用，那么弹出
    if len(url_queue)==1:
        if url_queue[0] not in total_seen.keys():
            url_queue.pop(0)
    elif len(url_queue)==2:
        if url_queue[0] not in total_seen.keys():
            url_queue.pop(0)
            if url_queue[0] not in total_seen.keys():#弹出后如果第二个url也不可用
                url_queue.pop(0)
        elif url_queue[1] not in total_seen.keys():#第一个可用，而第二个不可用
            url_queue.pop(1)

    if len(url_queue) == 0:
        return None



    while(len(url_queue)>0): ####################### 变式；为了对全站搜索，将其本身的的主路径找出来
        ###############################################################################这里
        current_url = url_queue.pop(0)    #列表弹出第一个
                                         #把这个url代表的网页存储好
        urls=[]
        if current_url:
            session.headers.update({'referer': current_url})
        else:
            session.headers.update({'referer': 'https://www.google.com.hk/'})
        urls= get_urls(current_url)

        ############################################################################### 或这里
        for next_url in urls:
            r=valid_url(next_url,total_seen.keys())
            if r:
                url_queue.append(next_url)
                total_seen[next_url] = r
#        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
#            futures_to_url=[]
#            #for next_url in urls: #提取把这个url里链向的url
#            #    future_to_url = {executor.submit(get_content, url): url for url in URLS}
#            futures_to_url={executor.submit(valid_url,next_url,total_seen.keys()):next_url for next_url in urls}
#            for future in concurrent.futures.as_completed(futures_to_url): #人家函数就要求list
#                r=future.result()
#                if r:
#                    temp_url=futures_to_url[future]
#                    url_queue.append(temp_url)#需要继续深挖的网站
#                    total_seen[temp_url] = r #seen.add(next_url)#我希望它只存储有效网站
                            #每次找到新网站，都知道他已经看过了// 并且它将作为新的深挖对象
                            #另外，如果是已经看过的网站，则已经没有必要再次深挖
                            
    return# total_seen

def valid_url(next_url,dict_keys):
    if next_url.startswith("javascript:"):
        logger.warning("just a javascript function - > %s\n",next_url)#print("a javascript function",next_url)
        return None
    if next_url not in dict_keys : #似乎不会有少的情况出现？
        ################# 即使是html似乎也可以搜集到东西
        #if next_url.endswith(".html"):
        #    logger.warning("just returns a html - > %s\n",next_url)#print("only returns a html",next_url)
        #    return None
        ####################
        try:
            session.headers.update({'User-Agent':get_random_ua()})
            
            #应该都是从current_url生成的url
            r = session.get(url=next_url,timeout=(5, 10),proxies=get_random_proxies())
            r.raise_for_status()#这一步如果是302，也会变成200；但是似乎影响并不大的样子？？
            #if r.status_code<300:
            if r.cookies: # 如果没有登录的话一般给没用的cookies; 登录的话我看了，似乎就不会再set了
                session.cookies=r.cookies
            if 'text/html'in r.headers.get('content-type'):#可能其中还有些纰漏（比如，不是反向直接排除而是正向排除）

                logger.info("valid url - > %s\n",next_url)#print("valid url - >",next_url)
                return r
      
            else:
                logger.debug("valide response but not refer to html - > %s\n",next_url)#print("valide response but not refer to html - >",next_url)
                return None
            #else:
            #    logger.warning("invalid response - > %s",next_url)#print("invalid response - > ",next_url)
            #        return None
        
        except requests.exceptions.ConnectionError as e:
            logger.critical("Connection Error - > %s with exception %s\n",next_url,e)
        except requests.exceptions.HTTPError as e:
            logger.warning("bad status code - > %s with exception %s\n",next_url,e)
        except requests.exceptions.TooManyRedirects as e:
            logger.error("Too many redirects - > %s with exception %s\n",next_url,e)
 #       except Exception as e:
 #           logger.critical("unknown error - > %s with exception %s\n",next_url,e)#print("unknown error - > ",next_url,e)
 #           return None
    

def get_urls(base_url):
    '''
    param base_url:给定一个网址
    return获取给定网址中的所有链接
    '''
    urls=[]
    try:
        session.headers.update({'User-Agent':get_random_ua()})

        res = session.get(url=base_url,timeout=(5, 10),proxies=get_random_proxies())
        res.raise_for_status()
        if res.cookies:
            session.cookies=res.cookies
        #if res.status_code<300:
        html=etree.HTML(res.content)#content是二进制流；对二进制流才能进行解析；
        #html = etree.parse(base_url, etree.HTMLParser())
        #html=lxml.html.parse
        result = html.xpath('//a/@href')
        #reg = '<a.+?href=\"(.+?)\".*>'
        for url in result:#re.search(reg, text).group():
            if url != '../':#如果不是向上返回的路径
                if 'http' or 'https' not in url:#如果是以相对路径的形式
                    urls.append(urljoin(base_url,url))
                    #if url.startswith('/'):#对于这种情况的判断'http://49.233.168.44/home_page/2018213701//notice'
                    #    urls.append(base_url + url)
                    #else:
                    #    urls.append(base_url +'/'+ url)
                else:#如果是绝对路径那么直接写入就好了
                    urls.append(url)
        return urls

    except requests.exceptions.ConnectionError as e:
        logger.critical("Connection Error - > %s with exception %s\n",base_url,e)
    except requests.exceptions.HTTPError as e:
        logger.warning("bad status code - > %s with exception %s\n",base_url,e)
    except requests.exceptions.TooManyRedirects as e:
        logger.error("Too many redirects - > %s with exception %s\n",base_url,e)
#    except Exception as e:
#        logger.critical("unkown error - > %s with exception %s\n",base_url,e)#print("unkown error - > ",base_url,e)

    return urls#??????????????????????????????????????????????????????????????????????????

def get_random_ua():
    with open(r"D:\myCTF\scanner\my\user-agents.txt","r") as fd:
        nb = 0#用来测到底这个用户代理的txt有多少行
        for l in fd:
            nb += 1
        fd.seek(0)#从文件开头开始
        nb = random.randint(0, nb)#反正随机取了一个数
        for i in range(0, nb):#0至nb-1
            userAgent = fd.readline()[:-1]#字符串切片操作，把最后那个空格省略
    return str(userAgent)
    #ua=UserAgent()#想搞个随机UA 好像没戏

def get_random_proxies():
    r = requests.get('http://127.0.0.1:8000/')#本来也就没几个'http://127.0.0.1:8000/?types=0&count=5&country=国内'
    
    if r.status_code>300:
        return {}
    ip_ports = json.loads(r.text)
    nb=0
    for i in r:
        nb+=1
    nb = random.randint(0, nb)
    ip = ip_ports[nb][0]
    port = ip_ports[nb][1]
    proxies={
    'http':'http://%s:%s'%(ip,port),    #特别学习：字典可以这么写
    'https':'http://%s:%s'%(ip,port)
        }
    return proxies

if __name__ == '__main__':
    total_seen = {}
    session = requests.Session()
    ###############设置最大重复次数，一共重复四次

    session.mount('http://', HTTPAdapter(max_retries=3))
    session.mount('https://', HTTPAdapter(max_retries=3))
    url = input("please input url:")
    _ = dict(session='.eJwljztuQzEMBO-i2gUpkSLpi6Q0JJJKjCAfvGdXQe4eASkX2Bns_pTbOvJ8K9fH8cxLud2jXIsKT2wu1BubVBVXbIsmUErvfUZ1GJ4R1lBIEECpGSl1dHOvpGnDa3guXhMNW59Qu-wKmGrX6SSDNTHMdKabsOXwAO4cTOVS_DzW7fH1np97T8LIqrQMYlCLuaU5pgazBjWdfYVVktjc_WO85kZ4fdeXnZ9nHv-nKqBWbAJYfv8AWldEvg.XekwuQ.wCTpj9hvBIlC3wqx-EtkNkYYs24')#; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')#PHPSESSID='bhvb21iekc4s0p6pnbqp6e4na3)#session='.eJwlzztuAzEMBNC7qHYhkqJE-ShpFhI_sRHEAXbtwghyd8tIOcUbzPymLXY_Lul83x9-StvV0jmJCHbKDaX0EGQqNrtMHRWEwdog54iYswJOrqhos6k7CVkrXXsTf1vWRjXDqhBuUIIXKaAx3NSsjzZJVk0lgOxuWUvtVFpJp6THHtv958tvaw9WjhyTLYcQY_ZsoiTVqUAdYCLaCyEud_0en77Ix-X2nCs_Dt__T2EGQaCWIf29AN5YRR8.XefB7g.1a_c6rOf5YGWBNACqrwxvDT9i9U; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')#PHPSESSID='p3d8eh46u7gu6ob57tdvpjkir0')#session='.eJwlzztuAzEMBNC7qHYhkqJE-ShpFhI_sRHEAXbtwghyd8tIOcUbzPymLXY_Lul83x9-StvV0jmJCHbKDaX0EGQqNrtMHRWEwdog54iYswJOrqhos6k7CVkrXXsTf1vWRjXDqhBuUIIXKaAx3NSsjzZJVk0lgOxuWUvtVFpJp6THHtv958tvaw9WjhyTLYcQY_ZsoiTVqUAdYCLaCyEud_0en77Ix-X2nCs_Dt__T2EGQaCWIf29AN5YRR8.XefB7g.1a_c6rOf5YGWBNACqrwxvDT9i9U; remember_token=2018213701|fb0791ae6f8e336e0b9e102a45f460b72c0c9ed740899e408baa3ee36b33f5606a773a659b731268a937a9ec918627b936ef13eaa46e30e577bf4aa51a2249c9')####cookie必须是字典形式！None#
    cookies = requests.utils.cookiejar_from_dict(_)
    session.cookies=cookies#似乎如果不显式调用就不会更新；而且放在session中的不会保持（虽然和之前那个也没什么关系）
    session.max_redirects = 3 #设置最大重定向次数
    scrape(url)

    if total_seen:
        logger.info("you have some results:\n")
        for key in total_seen.keys():
            print(key)
    else:
        logger.warning("we found nothing\n")
    
    logger.info("Now, make your choice: ")
    print("1. Perform SQL injection scans of all urls ")
    print("2. Input a url to perform SQL injection scans")
    print("3. exit")
    choice = input("your choice: ")
    if choice == "1":
        i = 1
        for myurl in total_seen.keys():
            print("[+]The %d url: %s" % (i,myurl))
            i += 1
            print("%d" % i)
            doc = lxml.html.parse(myurl)
            form = doc.xpath('//input')
            for i in range(len(form)):
                if 'name' in form[i].attrib: 
                    print(form[i].attrib['name'])
            data = ""
            for i in range(len(form)):
                if 'name' in form[i].attrib:
                    data += form[i].attrib['name'] + "=&"
            arg_list = '-u '+myurl+' -d '+data
            arg_list = arg_list.split(" ")
            mysql(arg_list)
        print("[+]Down")
    elif choice == "2":
        myurl = input("Please input your url: ")
        doc = lxml.html.parse(myurl)
        form = doc.xpath('//input')
        for i in range(len(form)):
            if 'name' in form[i].attrib:
                print(form[i].attrib['name'])
        data = ""
        for i in range(len(form)):
            if 'name' in form[i].attrib:
                data += form[i].attrib['name'] + "=&"
        arg_list = '-u '+myurl+' -d '+data
        arg_list = arg_list.split(" ")
        mysql(arg_list)
    else:
        print("Bye~~ :)")
        exit(0)

    # 放在内存中一份； 再放到文件中一份
    # 如果有该文件名的话，那么就不再生成；
    # 文件名应该是某个固定网站的根url（比如当前输入的url）
