#!/usr/bin/python3
#   coding: utf-8

import argparse
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
import time as tm
import sys
import socket
import hashlib
import threading as thrd
from multiprocessing import Process, Value, Array, Queue
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import ctypes

class URLList:
    visitedUrls = []
    multi = ''
    urllstreqque = None
    urllstrspque = None
    queproc = None

    def __is_visited(self, requrl):
        requrl.strip()
        if 64 < len(requrl):
            tag = mk_hash(requrl)
            #print('__is_visited tag:{}'.format(self), file=sys.stderr)
            #print('__is_visited [{}] tag: {}'.format(len(self.visitedUrls),tag), file=sys.stderr)
            if tag in self.visitedUrls:
                #print(f'Already {requrl}:{tag}', end='')
                #print('REF True [{}][{}]{}'.format(len(requrl),tag,requrl), file=sys.stderr)
                return True
            #print('REF False [{}][{}]{}'.format(len(requrl),tag,requrl))
        else:
            #print('__is_visited url:{}'.format(self), file=sys.stderr)
            #print('__is_visited [{}] url: {}'.format(len(self.visitedUrls),requrl), file=sys.stderr)
            if requrl in self.visitedUrls:
                #print(f'Already {requrl}', end='')
                #print('REF True [{}]{}'.format(len(requrl),requrl), file=sys.stderr)
                return True

        return False

    def __visitor_registration(self, requrl):
        requrl.strip()
        if 64 < len(requrl):
            tag = mk_hash(requrl)
            #print('__visitor_registration tag:{}:{}'.format(self,len(self.visitedUrls), file=sys.stderr)
            if not tag in self.visitedUrls:
                #print('__visitor_registration tag: {}'.format(tag), file=sys.stderr)
                self.visitedUrls.append(tag)
        else:
            #print('__visitor_registration url:{}:{}'.format(self,len(self.visitedUrls), file=sys.stderr)
            if not requrl in self.visitedUrls:
                #print('__visitor_registration url: {}'.format(requrl), file=sys.stderr)
                self.visitedUrls.append(requrl)
        #print('__visitor_registration last value[{}]: {}'.format(len(self.visitedUrls),self.visitedUrls[-1]), file=sys.stderr)
        pass

    def __urllst_queproc(self, reqque, rspque):
        print('Start __urllst_queproc')
        #print('Start __urllst_queproc', file=sys.stderr)
        while True:
            reqdat = reqque.get()
            if reqdat[0] == 'check':
                rtn = self.__is_visited(reqdat[1])
                rspque.put(rtn)
                pass
            elif reqdat[0] == 'regst':
                self.__visitor_registration(reqdat[1])
                rspque.put('ok')
                pass
            elif reqdat[0] == 'quit':
                break;

    def __init__(self, multi):
        self.multi = multi
        if multi != 'none':
            self.urllstreqque = Queue()
            self.urllstrspque = Queue()
            #self.queproc = Process(target=self.__urllst_queproc, args=[self.urllstreqque, self.urllstrspque])
            self.queproc = thrd.Thread(target=self.__urllst_queproc, args=[self.urllstreqque, self.urllstrspque])
            self.queproc.start()
        pass


    def is_visited(self, requrl):
        if self.multi == 'none':
            return self.__is_visited(requrl)
        else:
            self.urllstreqque.put(('check',requrl))
            #rsp = self.urllstrspque.get(timeout=3)
            rsp = self.urllstrspque.get()
            #print('is_visited rsp:{}:{}:{}'.format(type(rsp),dir(rsp),rsp))
            return rsp
        pass

    def visitor_registration(self, requrl):
        if self.multi == 'none':
            self.__visitor_registration(requrl)
        else:
            self.urllstreqque.put(('regst',requrl))
            rsp = self.urllstrspque.get(timeout=3)
        pass

    def procquit(self):
        #print('URLList.procquit()')
        self.urllstreqque.put(('quit',0))
        self.queproc.join()

class EXEqueue:
    exequeue = None
    exereq = None
    enqrsp = None
    deqrsp = None
    queproc = None

    def __exeque_proc(self, reqque, enqrsp, deqrsp):
        print('Start __exeque_proc')
        while True:
            #print("__exeque_proc: qsize {}".format(self.exequeue.qsize()))
            reqdat = reqque.get()

            if reqdat[0] == 'enque':
                #print("__exeque_proc recv:{}/{}".format(reqque.qsize(), reqdat))
                self.exequeue.put(reqdat[1])
                rspdat = ('enque', True)
                #print('enque resp:{}'.format(rspdat))
                enqrsp.put(rspdat)
                pass

            elif reqdat[0] == 'deque':
                #print("__exeque_proc recv:{}/{}".format(reqque.qsize(), reqdat))
                if self.exequeue.empty():
                    rspdat = ('deque', None)
                    deqrsp.put(rspdat)
                    continue
                que = self.exequeue.get()
                rspdat = ('deque', que)
                #print('deque resp:{}'.format(rspdat))
                deqrsp.put(rspdat)
                pass

            elif reqdat[0] == 'quit':
                while not self.exequeue.empty():
                    reqdat = self.exequeue.get_nowait()
                    print("Ignor:{}".format(reqdat))
                break
            else:
                print("__exeque_proc recv:{}/{}".format(reqque.qsize(), reqdat))
                pass

    def __init__(self, multi):
        if multi != 'none':
            self.exequeue = Queue()
            self.exereq = Queue()
            self.enqrsp = Queue()
            self.deqrsp = Queue()
            self.queproc = thrd.Thread(target=self.__exeque_proc, args=[self.exereq, self.enqrsp, self.deqrsp])
            self.queproc.start()

    def enque(self, exeinf):
        reqdat = ('enque', exeinf)
        #print("enque send:{}".format(reqdat))
        self.exereq.put(reqdat)
        rsp = self.enqrsp.get()
        #print('enqueue rtn:{}'.format(rsp))

    def deque(self):
        reqdat = ('deque',0)
        #print("deque send:{}".format(reqdat))
        self.exereq.put(reqdat)
        rsp = self.deqrsp.get()
        #print('dequeue rtn:{}'.format(rsp))
        return rsp[1]

    def procquit(self):
        #print('EXEqueue.procquit()')
        reqdat = ('quit',0)
        self.exereq.put(reqdat)
        self.queproc.join()
        #print('EXEqueue.procquit() END')

#strurl = 'https://chiaki.sakura.ne.jp'
#strurl = 'https://www.miharu.co.jp'

maxtabs = 16
maxofthread = 0
maxofprocs = 0
exectr = None
logout = ''
exeque = None

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
    aftm = tm.time()
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


def waitForEveryone2Join(thrdtbl, vl_numofprcs):
    if logout:
        print('waitForEveryone2Join:{} <<<'.format(len(thrdtbl)))

    while thrdtbl:
        proc = thrdtbl.pop()
        proc[0].join()
        with vl_numofprcs.get_lock():
            if 0 < vl_numofprcs.value:
                vl_numofprcs.value -= 1

    if logout:
        print('waitForEveryone2Join:{} >>>'.format(len(thrdtbl)))

def waitForEveryone2Result(exectr, thrdtbl, vl_numofprcs):
    if logout:
        print('waitForEveryone2Result:{} <<<'.format(len(thrdtbl)))
    while thrdtbl:
        svtbl = []
        while thrdtbl:
            proc = thrdtbl.pop()
            try:
                proc[0].result(timeout=1)
            except:
                print("{}:{}:No result {}".format(proc[0], proc[0].running(), proc[0]._state))
                continue
            with vl_numofprcs.get_lock():
                if 0 < vl_numofprcs.value:
                    vl_numofprcs.value -= 1
                    print('-Submit: {}'.format(vl_numofprcs.value))

        if len(svtbl):
            thrdtbl = svtbl
    if logout:
        print('waitForEveryone2Result:{} >>>'.format(len(thrdtbl)))

def start_surf(thrdtbl,urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt):
    if multi == 'thrd':
        maxof = maxofthread
    elif multi == 'prcs':
        maxof = maxofprocs
    else:
        return False

    if maxof < vl_numofprcs.value:
        exeque.enque((nxturl, tabs, multi, nxtcntnt))
        return False
    else:
        try:
            if multi == 'thrd':
                proc = thrd.Thread(target=surf, args=[urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt])
            elif multi == 'prcs':
                proc = Process(target=surf, args=[urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt])
            else:
                return False
        except:
            print('Creat error:surf[{}${}]'.format(nxturl,nxtcntnt))
            return False

        thrdtbl.append((proc, nxturl+'$'+nxtcntnt))
        with vl_numofprcs.get_lock():
            vl_numofprcs.value += 1
        thrdtbl[-1][0].start()

        if maxof <= vl_numofprcs.value:
            waitForEveryone2Join(thrdtbl, vl_numofprcs)
            while vl_numofprcs.value < maxof:
                que = exeque.deque()
                if que:
                    try:
                        if multi == 'thrd':
                            proc = thrd.Thread(target=surf, args=[urllst,que[0],que[1],que[2],vl_numofprcs,que[3]])
                        elif multi == 'prcs':
                            proc = Process(target=surf, args=[urllst,que[0],que[1],que[2],vl_numofprcs,que[3]])
                        else:
                            return False
                    except:
                        print('Creat error:surf[{}${}]'.format(que[0],que[3]))
                        return False

                    thrdtbl.append((proc, nxturl+'$'+nxtcntnt))
                    with vl_numofprcs.get_lock():
                        vl_numofprcs.value += 1
                    thrdtbl[-1][0].start()
                else:
                    break
        return True

#def surf(visitedUrls, url, level, multi, vl_numofprcs, cntnt=""):
def surf(urllst, url, level, multi, vl_numofprcs, cntnt=""):
    global maxtabs, exectr, maxofprocs, maxofthread, logout, exeque

    if (multi == 'thrdpl') or (multi == 'prcspl'):
        print('Start:[{}]{}'.format(level, url))

    logline = ''

    thrdtbl = []

    tabs = level

    if maxtabs <= tabs:
        return True

    ignr = ignor_domain(url)
    if 0 < len(ignr):
        print('Ignor:{} server is {}'.format(url,ignr))
        return True

    if 0 < len(cntnt) and '#' in cntnt:
        return True

    tabstr = tabspace(tabs)

    if 0 < len(cntnt):
        requrl = '{}/{}'.format(url,cntnt)
    else:
        requrl = url

    for imageattr in imageAttrs:
        chkstr = str.lower(requrl)
        imgfile = chkstr.rfind(imageattr)
        if 0 <= imgfile:
            return False

    if urllst.is_visited(requrl):
        #print(', So ignor.')
        return True

    #print('{}{}:'.format(tabstr,tabs), end='')
    logline = '{}{}:'.format(tabstr,tabs)
    if len(cntnt) == 0:
        #print('[{}]'.format(url), end='', flush=True)
        logline += '[{}]'.format(url)
    else:
        #print('[{}]/[{}]'.format(url,cntnt), end='', flush=True)
        logline += '[{}]/[{}]'.format(url,cntnt)

    urllst.visitor_registration(requrl)
    tabs += 1

    if logout:
        print('<{}'.format(requrl), file=sys.stderr)
    bftm = tm.time()
    try:
        resp = urllib.request.urlopen(requrl, timeout=16)
    except Exception as er:
        #print(' X {}:{}'.format(dlttime(bftm),er))
        logline += ' X {}:{}'.format(dlttime(bftm),er)
        if 0 < tabs:
            tabs -= 1
        print(logline)
        return False;
    if logout:
        print('>{}'.format(requrl), file=sys.stderr)

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
        return False;

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

            if (multi == 'thrd') or (multi == 'prcs'):
                rtn = start_surf(thrdtbl,urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)
                if rtn == False:
                    continue
                pass

            elif (multi == 'thrdpl') or (multi == 'prcspl'):
                try:
                    proc = exectr.submit(surf, urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)
                except:
                    logline += 'Submit fail:{}'.format(nxturl)
                    print(logline)
                    continue
                if proc:
                    thrdtbl.append((proc, nxturl+'$'+nxtcntnt))
                    with vl_numofprcs.get_lock():
                        vl_numofprcs.value += 1
                    #print('+Submit:{} multi:{} maxofthread:{} maxofprocs:{}'.format(vl_numofprcs.value, multi, maxofthread, maxofprocs))
                    if (multi == 'thrdpl') and (maxofthread <= vl_numofprcs.value):
                        waitForEveryone2Result(exectr, thrdtbl, vl_numofprcs)
                    elif (multi == 'prcspl') and (maxofprocs <= vl_numofprcs.value):
                        waitForEveryone2Result(exectr, thrdtbl, vl_numofprcs)
                    else:
                        pass
                else:
                    logline += 'Submit None:{}'.format(nxturl)
                    print(logline)
                pass
            else:
                #print(f'{nxturl}@{nxtcntnt}')
                surf(urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)
                #print('--'*tabs)

    if (multi == 'thrd') or (multi == 'prcs'):
        if multi == 'thrd':
            maxof = maxofthread
        else:
            maxof = maxofprocs
        que = exeque.deque()
        while que:
            if multi == 'thrd':
                thrdtbl.append((thrd.Thread(target=surf, args=[urllst,que[0],que[1],que[2],vl_numofprcs,que[3],]), '$'))
            else:
                thrdtbl.append((Process(target=surf, args=[urllst,que[0],que[1],que[2],vl_numofprcs,que[3],]), '$'))
            with vl_numofprcs.get_lock():
                vl_numofprcs.value += 1
            thrdtbl[-1][0].start()

            if maxof <= vl_numofprcs.value:
                waitForEveryone2Join(thrdtbl, vl_numofprcs)

            que = exeque.deque()

        waitForEveryone2Join(thrdtbl, vl_numofprcs)

    elif (multi == 'thrdpl') or (multi == 'prcspl'):
        waitForEveryone2Result(exectr, thrdtbl, vl_numofprcs)

    if 0 < tabs:
        tabs -= 1

    print(logline)
    return True

def main():
    #global maxtabs, exectr, visitedUrls
    global maxtabs, exectr, maxofprocs, maxofthread, logout, exeque
    argp = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                    description='指定のコンテンツからリンクされているコンテンツを辿り渡る')
    argp.add_argument('url', metavar='<URL>', help='開始URL')
    argp.add_argument('-lvl', '--linklevel', type=int, default=16, help='辿る深さ')
    argp.add_argument('-mlt', '--multi', choices=['thrd','prcs','prcspl','thrdpl','none'], default='none', help='並列処理を有効にする')
    argp.add_argument('-mxps', '--maxprocs', type=int, default=2, help='並列処理最大生成数')
    argp.add_argument('-mxtd', '--maxthread', type=int, default=8, help='並行処理最大生成数')
    argp.add_argument('-lgot', '--logout', action='store_true', help='ログ出力先')

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
    maxofprocs = args.maxprocs
    maxofthread = args.maxthread
    logout = args.logout

    vl_numofprcs = Value(ctypes.c_int, 0)
    urllst = URLList(args.multi)
    exeque = EXEqueue(args.multi)

    if (args.multi == 'prcspl') or (args.multi == 'thrdpl'):
        if args.multi == 'thrdpl':
            exectr = ThreadPoolExecutor(max_workers=maxofthread)
            #exectr = ThreadPoolExecutor()
        else:
            exectr = ProcessPoolExecutor(max_workers=maxofprocs)

    surf(urllst, strurl, 0, args.multi, vl_numofprcs)

    if (args.multi == 'prcspl') or (args.multi == 'thrdpl'):
        print('<Shutdown>')
        exectr.shutdown()

    if args.multi != 'none':
        urllst.procquit()
        exeque.procquit()

# main
if __name__ == '__main__':
    main()
    print('end')

exit()
