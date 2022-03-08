#!/usr/bin/python3
#   coding: utf-8

import urllib.request
import urllib.parse
import time
import sys

strurl = 'https://chiaki.sakura.ne.jp'
#strurl = 'https://www.miharu.co.jp'

tabs = 0
maxtabs = 32

serchHrefs = ('href="', 'HREF="')
serchHttps = ('http://', 'https://')
cntntAttrs = ('.html', '.shtml')
imageAttrs = ('mailto:', 'javascript:', '.jpg', '.png', '.mpeg', '.img', '.mp4', '.mov',
 '.mp3', '.m4a', '.aiff', '.wav', '.ico', '.css', '.pdf', '.doc', '.docx',
  '.xls')

visitedUrls = []

def surf(url, cntnt=""):
    global tabs
    global maxtabs

    if maxtabs <= tabs:
        return

    if 0 < len(cntnt) and '#' in cntnt:
        return

    tabstr = ''
    if 0 < tabs:
        tabstr = '  ' * tabs

    if 0 < len(cntnt):
        requrl = f'{url}/{cntnt}'
    else:
        requrl = url

    for imageattr in imageAttrs:
        chkstr = str.lower(requrl)
        imgfile = chkstr.rfind(imageattr)
        if 0 <= imgfile:
            return

    if requrl in visitedUrls:
        return

    print(f'{tabstr}{tabs}:', end='')
    if len(cntnt) == 0:
        print(f'[{url}]', end='', flush=True)
    else:
        print(f'[{url}]/[{cntnt}]', end='', flush=True)

    visitedUrls.append(requrl)
    tabs += 1

    bftm = time.time()
    try:
        resp = urllib.request.urlopen(requrl)
    except Exception:
        aftm = time.time()
        dlttm = aftm - bftm
        if 0 < tabs:
            tabs -= 1
        print(' X{t:8.4}'.format(t=dlttm))
        return;

    for html in cntntAttrs:
        ix = requrl.rfind(html)
        if (0 <= ix):
            ix = requrl.rfind('/')
            if (0 <= ix):
                url = requrl[:ix]

    try:
        content = resp.read()
    except Exception:
        resp.close()
        aftm = time.time()
        dlttm = aftm - bftm
        if 0 < tabs:
            tabs -= 1
        print(' X{t:8.4}'.format(t=dlttm))
        return;

    resp.close()

    aftm = time.time()
    dlttm = aftm - bftm
    print(' {t:8.4}'.format(t=dlttm))

    try:
        decdat = content.decode()
    except:
        try:
            decdat = content.decode('shift-jis')
        except Exception:
            if 0 < tabs:
                tabs -= 1
            return;

    lists = decdat.split('\n')
    for line in lists:
        for serchhref in serchHrefs:
            if serchhref in line:
                # href/HREF="---
                strclm = line.find(serchhref)   # -------href="-------
                                                #        ^-- strclm
                aftrline = line[strclm+(len(serchhref)):] # ----href="--------------
                                                          #           |- aftrline -|
                endclm = aftrline.find('"')     # |-aftrline--"----|
                                                #             ^-- endclm
                hrefstnc = aftrline[:endclm]    # |-aftrline--"----|
                                                # |-hrefstnc-|
                hrefstnc = hrefstnc.strip()
                #print(f'URL:{url} TARGET:{serchhref}{hrefstnc}')
                nxtcntnt = ""
                for serchhttp in serchHttps:
                    if serchhttp in hrefstnc[:len(serchhttp)]:
                        # http://----------, https://------------
                        nxturl = hrefstnc
                        break
                else:
                    # href sentence is relative path: a/b/c

                    # parameter url type check
                    for cntntattr in cntntAttrs:
                        urliscntnt = url.rfind(cntntattr)
                        if 0 <= urliscntnt:
                            # http://a/b/---.html or https://a/b/---.shtml
                            break

                    if urliscntnt < 0:
                        # parameter url is dir specify
                        # Use the href sentence URL as it is.
                        nxturl = url
                    else:
                        # parameter url is content specify
                        # Cut out content file name for the href sentence URL
                        midclm = url.rfind('/') # https://a/b/cntnt.shtml
                                                #            ^- midclm
                        if midclm < 0:
                            print(f'Illigal URL?:{url}')
                            if 0 < tabs:
                                tabs -= 1
                            return
                        else:
                            nxturl = f'{url[:midclm]}'  # https://a/b/cntnt.shtml
                                                        # |-nxturl--|

                    midclm = hrefstnc.find('/') # href sentnce: a/b/c
                                                #                ^-midclm
                    if midclm < 0:
                        # href sentnce is file specifycation only (href="a")
                        # Use next contnt
                        nxtcntnt = hrefstnc
                    else:
                        # href sentence is path specifycation (href="a/b/c")
                        # If first path name of next contnt and last path name of next urls
                        # is same, marge.
                        pathnm = hrefstnc[:midclm]  # href sentence: aaaaaaaaaa/b/c
                                                    #                |-pathnm-|
                        pathx = nxturl.rfind(pathnm) # https://..../..../aaaaaaaaaa
                                                     #                   ^-pathx
                        if pathx < 0:
                            # no same path in next url
                            nxtcntnt = hrefstnc
                        elif len(nxturl) == len(pathnm)+pathx:  # https://.../.../aaaaaaaaaaaaaaa
                                                                #                ^-pathx
                                                                #                 |-len(pathnm)-|
                            nxtcntnt = hrefstnc[midclm:]        # href sentence: aaaaaaaaaa/b/c
                                                                #                          ^-midclm
                                                                #                           |-next sentnce-|

                #print(f'SURF:{nxturl}@{nxtcntnt} -> ', end='')
                nxturl = nxturl.rstrip('/')
                nxtcntnt = nxtcntnt.lstrip('/')
                #print(f'{nxturl}@{nxtcntnt}')
                #print()

                surf(nxturl, nxtcntnt)
                #print('--'*tabs)

    if 0 < tabs:
        tabs -= 1
        
if (0 < len(sys.argv)):
    for (x, v) in enumerate(sys.argv):
        print (f'x:{x} v:{v}')
        if x == 1:
            strurl = v
        elif x == 2:
            maxtabs = int(v)

surf(strurl)
