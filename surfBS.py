#!/usr/bin/python3
#   coding: utf-8

import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
import time
import sys
import socket
import hashlib

#strurl = 'https://chiaki.sakura.ne.jp'
strurl = 'https://www.miharu.co.jp'

tabs = 0
maxtabs = 16

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
    hash = hashlib.shake_128()
    hash.update(requrl.encode())
    tag = hash.hexdigest(32)
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


def surf(url, cntnt=""):
    global tabs
    global maxtabs

    if maxtabs <= tabs:
        return

    ignr = ignor_domain(url)
    if 0 < len(ignr):
        print('Ignor:{} server is {}'.format(url,ignr))

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

    print('{}{}:'.format(tabstr,tabs), end='')
    if len(cntnt) == 0:
        print('[{}]'.format(url), end='', flush=True)
    else:
        print('[{}]/[{}]'.format(url,cntnt), end='', flush=True)

    visitor_registration(requrl)
    tabs += 1

    bftm = time.time()
    try:
        resp = urllib.request.urlopen(requrl)
    except Exception:
        print(' X {dlttime(bftm)}'.format(bftm))
        if 0 < tabs:
            tabs -= 1
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
        print(' X {dlttime(bftm)}'.format(bftm))
        if 0 < tabs:
            tabs -= 1
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

    print(' {}'.format(dlttime(bftm)))

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


            #print(f'{nxturl}@{nxtcntnt}')
            surf(nxturl, nxtcntnt)
            #print('--'*tabs)

    if 0 < tabs:
        tabs -= 1

    return


if (0 < len(sys.argv)):
    for (x, v) in enumerate(sys.argv):
        print ('x:{} v:{}'.format(x,v))
        if x == 1:
            strurl = v
        elif x == 2:
            maxtabs = int(v)

surf(strurl)
