#!/usr/bin/python3
#   coding: utf-8

import argparse
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
import time
import sys
import socket
import hashlib
import threading as thrd
from multiprocessing import Process
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor

#strurl = 'https://chiaki.sakura.ne.jp'
#strurl = 'https://www.miharu.co.jp'
maxtabs = 16
maxofthread = 128
maxofprocs = 6
numofprcs = 0
exectr = None

serchHrefs = ('href="', 'HREF="')
serchHttps = ('http://', 'https://')
cntntAttrs = ('.html', '.shtml')
imageAttrs = ('mailto:', 'javascript:', '.jpg', '.png', '.mpeg', '.img', '.mp4', '.mov',
 '.mp3', '.m4a', '.aiff', '.wav', '.ico', '.css', '.pdf', '.doc', '.docx',
  '.xls')

ignorHosts = ('akamai',)
def ignor_domain(url):
    if 0 < len(url):
        for http in serchHttps:
            chkstr = str.lower(url)
            strix = chkstr.find(http)
            if 0 <= strix:
                tlix = chkstr[strix+len(http):].find('/')
                if 0 < tlix:
                    domain = chkstr[strix+len(http):(strix+len(http))+tlix]
                else:
                    domain = chkstr[strix+len(http):]
                #print(f'domain:{domain}')
                try:
                    hostadr = socket.gethostbyname(domain)
                except:
                    hostadr = ""
                if 0 < len(hostadr):
                    #print(f'hostadr:{hostadr}')
                    try:
                        host = socket.gethostbyaddr(hostadr)[0]
                    except:
                        host = ""
                    if 0 < len(host):
                        for ignr in ignorHosts:
                            if ignr in host:
                                #print(f'{domain} is {ignr}:{host}')
                                return ignr
    return ""

def dlttime(bftm):
    aftm = time.time()
    dlttm = aftm - bftm
    return '{:08.4}'.format(dlttm)

def tabspace(tabs):
    tabstr = ''
    if 0 < tabs:
        if tabs <= 32:
            tabstr = '  '
        else:
            tabstr = ' '
        tabstr *= tabs
    return tabstr

def mk_hash(requrl):
    hash = hashlib.sha1()
    hash.update(requrl.encode())
    tag = hash.hexdigest()
    return tag

visitedUrls = []
def is_visited(requrl):
    if 64 < len(requrl):
        tag = mk_hash(requrl)
        if tag in visitedUrls:
            #print(f'Already {requrl}:{tag}', end='')
            return True
    else:
        if requrl in visitedUrls:
            #print(f'Already {requrl}', end='')
            return True
    return False

def visitor_registration(requrl):
    if 64 < len(requrl):
        tag = mk_hash(requrl)
        visitedUrls.append(tag)
    else:
        visitedUrls.append(requrl)

def waitForEveryone2Join(thrdtbl):
    global numofprcs
    while thrdtbl:
        thrdtbl.pop().join()
        if 0 < numofprcs:
            numofprcs -= 1

def surf(url, level, multi, cntnt=""):
    global maxtabs, exectr, numofprcs
    logline = ''

    thrdtbl = []

    tabs = level

    if maxtabs <= tabs:
        return

    ignr = ignor_domain(url)
    if 0 < len(ignr):
        print('Ignor:{} server is {}'.format(url,ignr))
        return

    if 0 < len(cntnt) and '#' in cntnt:
        return

    tabstr = tabspace(tabs)

    if 0 < len(cntnt):
        requrl = '{}/{}'.format(url,cntnt)
    else:
        requrl = url

    for imageattr in imageAttrs:
        chkstr = str.lower(requrl)
        imgfile = chkstr.rfind(imageattr)
        if 0 <= imgfile:
            return

    if is_visited(requrl):
        #print(', So ignor.')
        return

    #print('{}{}:'.format(tabstr,tabs), end='')
    logline = '{}{}:'.format(tabstr,tabs)
    if len(cntnt) == 0:
        #print('[{}]'.format(url), end='', flush=True)
        logline += '[{}]'.format(url)
    else:
        #print('[{}]/[{}]'.format(url,cntnt), end='', flush=True)
        logline += '[{}]/[{}]'.format(url,cntnt)

    visitor_registration(requrl)
    tabs += 1

    bftm = time.time()
    try:
        resp = urllib.request.urlopen(requrl)
    except Exception as er:
        #print(' X {}:{}'.format(dlttime(bftm),er))
        logline += ' X {}:{}'.format(dlttime(bftm),er)
        if 0 < tabs:
            tabs -= 1
        print(logline)
        return;

    for html in cntntAttrs:
        ix = requrl.rfind(html)
        if (0 <= ix):
            ix = requrl.rfind('/')
            if (0 <= ix):
                url = requrl[:ix]

    try:
        contnt = BeautifulSoup(resp, features='html.parser')
    except:
        resp.close()
        #print(' X {}:{}'.format(dlttime(bftm)))
        logline += ' X {}:{}'.format(dlttime(bftm))
        if 0 < tabs:
            tabs -= 1
        print(logline)
        return;

    atags = contnt.find_all('a')
    Atags = contnt.find_all('A')
    atags.append(Atags)
    tagstrs = []
    for tag in atags:
        for href in serchHrefs:
            tagstrs.append(str(tag))
            strx = tagstrs[-1].find(href)
            if 0 <= strx:
                tagstrs[-1] = tagstrs[-1][strx+len(href):]
                endx = tagstrs[-1].find('"')
                if 0 <= endx:
                    tagstrs[-1] = tagstrs[-1][:endx]
                else:
                    del tagstrs[-1]

                break
            else:
                del tagstrs[-1]
        else:
            continue

    resp.close()

    #print(' {}'.format(dlttime(bftm)))
    logline += ' {}'.format(dlttime(bftm))

    for tagstr in tagstrs:
        if len(tagstr):
            tagstr = tagstr.strip()
            httplen = -1
            for http in serchHttps:
                if tagstr[:len(http)] == http:
                    httplen = len(http)
                    nxturl = tagstr
                    nxtcntnt = ""
                    break
            else:
                nxturl = url;
                for http in serchHttps:
                    if url[:len(http)] == http:
                        httplen = len(http)
                        break

                nxtcntnt = tagstr

            if len(nxtcntnt):
                if nxtcntnt[0] == '/':
                    if 0 <= httplen:
                        ix = nxturl[httplen:].find('/')
                        if 0 <= ix:
                            nxturl = nxturl[:httplen+ix]
                        else:
                            nxturl = nxturl.rstrip('/')
                    else:
                        nxturl = nxturl.rstrip('/')
                else:
                    nxturl = nxturl.rstrip('/')

                nxtcntnt = nxtcntnt.lstrip('/')
            else:
                nxturl = nxturl.rstrip('/')

            if multi == 'thrd':
                thrdtbl.append(thrd.Thread(target=surf, args=[nxturl, tabs, multi, nxtcntnt]))
                thrdtbl[-1].start()
                pass
            elif multi == 'prcs':
                try:
                    proc = Process(target=surf, args=[nxturl, tabs, multi, nxtcntnt])
                except:
                    #print('Process fail:{}'.format(nxturl))
                    logline += 'Process fail:{}'.format(nxturl)
                    print(logline)
                    continue
                if proc:
                    thrdtbl.append(proc)
                    numofprcs += 1
                    thrdtbl[-1].start()
                    if (maxofprocs <= numofprcs):
                        waitForEveryone2Join(thrdtbl)
                else:
                    logline += 'Process NULL:{}'.format(nxturl)
                    print(logline)
                pass
            elif (multi == 'thrdpl') or (multi == 'prcspl'):
                pass
            else:
                #print(f'{nxturl}@{nxtcntnt}')
                surf(nxturl, tabs, multi, nxtcntnt)
                #print('--'*tabs)

    if (multi == 'thrd') or (multi == 'prcs'):
        waitForEveryone2Join(thrdtbl)
    elif (multi == 'thrdpl') or (multi == 'prcspl'):
        for t in thrdtbl:
            t.result(timeout=None)
        exectr.shutdown()

    if 0 < tabs:
        tabs -= 1

    print(logline)
    return

def main():
    global maxtabs, exectr
    argp = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                    description='指定のコンテンツからリンクされているコンテンツを辿り渡る')
    argp.add_argument('url', metavar='<URL>', help='開始URL')
    argp.add_argument('-lvl', '--linklevel', type=int, default=16, help='辿る深さ')
    argp.add_argument('-mlt', '--multi', choices=['thrd','prcs','prcspl','thrdpl','none'], default='none', help='並列処理を有効にする')

    args = argp.parse_args()
    #print('args:{}'.format(args))

    strurl = args.url
    httpprfx = 'http://'
    httplen = len(httpprfx)
    if (httplen <= len(strurl)) and (httpprfx != strurl[:httplen]):
        httpprfx = 'https://'
        httplen = len(httpprfx)
        if (httplen <= len(strurl)) and (httpprfx != strurl[:httplen]):
            strurl = httpprfx + strurl
        elif len(strurl) < httplen:
            strurl = httpprfx + strurl
    elif len(strurl) < httplen:
        strurl = 'https://' + strurl
    #print('URL:{}'.format(strurl))

    maxtabs = args.linklevel

    if (args.multi == 'prcspl') or (args.multi == 'thrdpl'):
        if args.multi == 'thrdpl':
            exectr = ThreadPoolExecutor(max_workers=maxofthread)
        else:
            exectr = ProcessPoolExecutor(max_workers=maxofprocs)

    surf(strurl, 0, args.multi)

# main
if __name__ == '__main__':
    main()
