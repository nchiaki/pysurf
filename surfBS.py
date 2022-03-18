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
                    print("Ignor by quit:{}".format(reqdat))
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

    def is_empty(self):
        if self.exequeue.empty():
            return True
        else:
            return False


#strurl = 'https://chiaki.sakura.ne.jp'
#strurl = 'https://www.miharu.co.jp'

maxtabs = 16
maxofthread = 0
maxofprocs = 0
exectr = None
logout = ''
exeque = None
_urllst = None
_vl_numofprcs = None

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
    #return '{:08.4}'.format(dlttm)
    return '@'

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


def waitForEveryone2Join(me, thrdtbl, vl_numofprcs):
    if logout:
        print('waitForEveryone2Join:{} <<<'.format(len(thrdtbl)))

    iam = None

    while thrdtbl:
        proc = thrdtbl.pop()
        if proc[1] == me:
            iam = proc
            continue

        proc[0].join()
        with vl_numofprcs.get_lock():
            if 0 < vl_numofprcs.value:
                vl_numofprcs.value -= 1

        #print('[{}]{}: remove from waitForEveryone2'.format(me,proc[1]))

    if iam:
        thrdtbl.append(iam)
    '''
    while thrdtbl:
        svtbl = []
        while thrdtbl:
            proc = thrdtbl.pop()
            try:
                proc[0].join(timeout=1.0)
            except Exception as er:
                if proc[0].running():
                    print("{} {}:{} No join {}".format(er, proc[0], proc[0].running(), proc[0]._state))
                    svtbl.append(proc)
                    continue

            with vl_numofprcs.get_lock():
                if 0 < vl_numofprcs.value:
                    vl_numofprcs.value -= 1
        if len(svtbl):
            thrdtbl = svtbl
            print('After {} threads/procs'.format(len(svtbl)))
        '''

    if logout:
        print('waitForEveryone2Join:{} >>>'.format(len(thrdtbl)))

def waitForEveryone2Result(me, thrdtbl, vl_numofprcs):
    if logout:
        print('waitForEveryone2Result:{} <<<'.format(len(thrdtbl)))

    iam = None
    premsg = ''
    while thrdtbl:
        svtbl = []
        while thrdtbl:
            proc = thrdtbl.pop()
            if proc[1] == me:
                iam = proc
                continue

            try:
                proc[0].result(timeout=1.0)
            except Exception as er:
                if proc[0].running():
                    '''
                    msg = "{} {}:{} No result {}".format(er, proc[1], proc[0].running(), proc[0]._state)
                    if premsg != msg:
                        print(msg)
                        premsg = msg
                    '''
                    svtbl.append(proc)
                    continue

            with vl_numofprcs.get_lock():
                if 0 < vl_numofprcs.value:
                    vl_numofprcs.value -= 1
                    #print('-Submit: {}'.format(vl_numofprcs.value))

            #print('[{}]{}: remove from waitForEveryone2'.format(me,proc[1]))

        if len(svtbl):
            thrdtbl = svtbl
            #print('After {} threads/procs'.format(len(svtbl)))

    if iam:
        thrdtbl.append(iam)

    if logout:
        print('waitForEveryone2Result:{} >>>'.format(len(thrdtbl)))

def waitForEveryone2Nowait(me, thrdtbl, vl_numofprcs):
    premsg = ''
    for proc in thrdtbl:
        if proc[1] == me:
            thrdtbl.remove(me)
            with vl_numofprcs.get_lock():
                if 0 < vl_numofprcs.value:
                    vl_numofprcs.value -= 1
            '''
            msg = '[{}]{}: remove from waitForEveryone2'.format(me,proc[1])
            if premsg != msg:
                print(msg)
                premsg = msg
            '''
            break

def surf_prcspool(me, nxturl, tabs, multi, nxtcntnt):
    global _urllst, _vl_numofprcs

    rtn = surf(me, _urllst, nxturl, tabs, multi, _vl_numofprcs, cntnt=nxtcntnt)

    return rtn

def maxof_waitForEveryone2(multi):
    if multi == 'thrd':
        return maxofthread, waitForEveryone2Join
    elif multi == 'prcs':
        return maxofprocs, waitForEveryone2Join
    elif multi == 'thrdpl':
        return maxofthread, waitForEveryone2Result
    elif multi == 'prcspl':
        return  maxofprocs, waitForEveryone2Nowait
    else:
        return 0, None

def start_surf(me, thrdtbl,urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt):
    maxof, waitForEveryone2 = maxof_waitForEveryone2(multi)
    if waitForEveryone2 == None:
        return False

    #print('Start[{}] {}/{}'.format(me, vl_numofprcs.value, maxof))

    if maxof < vl_numofprcs.value:
        #print('Enqueu[{}] {}:{}:{}:{}'.format(me, nxturl, tabs, multi, nxtcntnt))
        exeque.enque((me, nxturl, tabs, multi, nxtcntnt))
        return False
    else:
        #print('Fire[{}] {}:{}:{}:{}'.format(me, nxturl, tabs, multi, nxtcntnt))
        try:
            you = tm.time()
            if multi == 'thrd':
                proc = thrd.Thread(target=surf, args=[you, urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt])
            elif multi == 'prcs':
                proc = Process(target=surf, args=[you, urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt])
            elif multi == 'thrdpl':
                proc = exectr.submit(surf, you, urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)
            elif multi == 'prcspl':
                #print('IN submit[{}]'.format(me))
                proc = exectr.submit(surf_prcspool, you, nxturl, tabs, multi, nxtcntnt, timeout=3.0)
                #print('OUT submit[{}]:{}'.format(me,you))
            else:
                return False
        except Exception as er:
            print('Creat error[{}] {}:surf[{}${}]'.format(me,er,nxturl,nxtcntnt))
            exeque.enque((me, nxturl, tabs, multi, nxtcntnt))
            return False

        #print('start surf proc[{}]{}:{}${}'.format(me,you,nxturl,nxtcntnt))

        thrdtbl.append((proc, you))
        with vl_numofprcs.get_lock():
            vl_numofprcs.value += 1

        if (multi == 'thrd') or (multi == 'prcs'):
            thrdtbl[-1][0].start()

        if maxof <= vl_numofprcs.value:
            #print('waitForEveryone2[{}] {}/{}'.format(me,vl_numofprcs.value,maxof))
            waitForEveryone2(me, thrdtbl, vl_numofprcs)
            #print('Dequeue count info {}/{}'.format(vl_numofprcs.value,maxof))
            #while vl_numofprcs.value < maxof:
            que = exeque.deque()
            if que:
                you = tm.time()
                try:
                    if multi == 'thrd':
                        proc = thrd.Thread(target=surf, args=[you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4]])
                    elif multi == 'prcs':
                        proc = Process(target=surf, args=[you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4]])
                    elif multi == 'thrdpl':
                        proc = exectr.submit(surf, you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4])
                    elif multi == 'prcspl':
                        proc = exectr.submit(surf_prcspool, you,que[1],que[2],que[3],que[4], timeout=3.0)
                    else:
                        return False
                except Exception as er:
                    print('Creat error[{}]{}:surf[{}${}]'.format(me,er,que[1],que[4]))
                    exeque.enque((me,que[1],que[2],que[3],que[4]))
                    return False

                print('start surf deque proc[{}]{}:{}${}'.format(me,you,que[1],que[4]))

                thrdtbl.append((proc, you))
                with vl_numofprcs.get_lock():
                    vl_numofprcs.value += 1

                if (multi == 'thrd') or (multi == 'prcs'):
                    thrdtbl[-1][0].start()
            #else:
            #    break
        return True

def flush_surf(me, thrdtbl, urllst, multi, vl_numofprcs):
    maxof, waitForEveryone2 = maxof_waitForEveryone2(multi)
    if waitForEveryone2 == None:
        return False

    que = exeque.deque()
    while que:
        try:
            #print('Flush {}:{}:{}:{}:{}'.format(que[0],que[1],que[2],que[3],que[4]))
            you = tm.time()
            if multi == 'thrd':
                proc = thrd.Thread(target=surf, args=[you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4]])
            elif multi == 'prcs':
                proc = Process(target=surf, args=[you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4]])
            elif multi == 'thrdpl':
                proc = exectr.submit(surf, you,urllst,que[1],que[2],que[3],vl_numofprcs,que[4])
            elif multi == 'prcspl':
                proc = exectr.submit(surf_prcspool, you,que[1],que[2],que[3],que[4], timeout=3.0)
            else:
                return False
        except Exception as er:
                print('Creat error[{}]{}:surf[{}${}]'.format(me,er,que[1],que[4]))
                #exeque.enque((que[0],que[1],que[2],que[3]))
                que = exeque.deque()
                continue

        #print('start flush surf deque proc[{}]{}:{}${}'.format(me,you,que[1],que[4]))

        thrdtbl.append((proc, you))

        with vl_numofprcs.get_lock():
            vl_numofprcs.value += 1

        if (multi == 'thrd') or (multi == 'prcs'):
            thrdtbl[-1][0].start()

        if maxof <= vl_numofprcs.value:
            #print('flush_surf waitForEveryone2[{}] {}/{}'.format(me,vl_numofprcs.value,maxof))
            waitForEveryone2(me, thrdtbl, vl_numofprcs)

        que = exeque.deque()

    #print('flush_surf waitForEveryone2[{}]:{}'.format(me,vl_numofprcs.value))
    waitForEveryone2(me,thrdtbl,vl_numofprcs)


#def surf(visitedUrls, url, level, multi, vl_numofprcs, cntnt=""):
def surf(me, urllst, url, level, multi, vl_numofprcs, cntnt=""):
    global maxtabs, exectr, maxofprocs, maxofthread, logout, exeque

    #print('surf[{}]:{}${} tabs:{}/{}'.format(me,url,cntnt,level,maxtabs))

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
        #print('Already visited:{}',format(requrl))
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

    #print('surf[{}] URLS:{}'.format(me,len(tagstrs)))
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

            if multi != 'none':
                #print('IN start_surf[{}]'.format(me))
                rtn = start_surf(me, thrdtbl,urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)
                #print('OUT start_surf[{}]:{}'.format(me,rtn))

                if rtn == False:
                    continue
            else:
                surf(me, urllst, nxturl, tabs, multi, vl_numofprcs, nxtcntnt)

    if multi != 'none':
        flush_surf(me, thrdtbl,urllst, multi, vl_numofprcs)

    if 0 < tabs:
        tabs -= 1

    print(logline)
    return True

def main():
    #global maxtabs, exectr, visitedUrls
    global maxtabs, exectr, maxofprocs, maxofthread, logout, exeque, _urllst, _vl_numofprcs
    argp = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                    description='指定のコンテンツからリンクされているコンテンツを辿り渡る')
    argp.add_argument('url', metavar='<URL>', help='開始URL')
    argp.add_argument('-lvl', '--linklevel', type=int, default=16, help='辿る深さ')
    argp.add_argument('-mlt', '--multi', choices=['thrd','prcs','prcspl','thrdpl','none'], default='none', help='並列処理を有効にする')
    argp.add_argument('-mxps', '--maxprocs', type=int, default=4, help='並列処理最大生成数')
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
    _vl_numofprcs = vl_numofprcs
    urllst = URLList(args.multi)
    _urllst = urllst
    exeque = EXEqueue(args.multi)

    if (args.multi == 'prcspl') or (args.multi == 'thrdpl'):
        if args.multi == 'thrdpl':
            exectr = ThreadPoolExecutor(max_workers=maxofthread)
            #exectr = ThreadPoolExecutor()
        else:
            exectr = ProcessPoolExecutor(max_workers=maxofprocs)

    surf(tm.time(), urllst, strurl, 0, args.multi, vl_numofprcs)

    if (args.multi == 'prcspl') or (args.multi == 'thrdpl'):
        premsg = ''
        while vl_numofprcs.value or not exeque.is_empty():
            msg = '{} or empty {} more threads/procs <Shutdown>'.format(vl_numofprcs.value,exeque.is_empty())
            if premsg != msg:
                print(msg)
                premsg = msg
            tm.sleep(0.1)
        exectr.shutdown()

    if args.multi != 'none':
        urllst.procquit()
        exeque.procquit()

# main
if __name__ == '__main__':
    main()
    print('end')

exit()
