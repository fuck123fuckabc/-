import urllib2
import socket
import select
import sys
import threading
import getopt
import signal
import zlib
import re
import random


class RedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        return fp
        #pass
    def http_error_302(self, req, fp, code, msg, headers):
        #pass
        return fp


class ErrorHandler(urllib2.HTTPDefaultErrorHandler):
    def http_error_default(self, req, fp, code, msg, headers):
        return fp


defaultsecond = 2
fw = 0
l = threading.RLock()
TotalList = []
portlist = []
scannum = 0
ListLine = 0
defaultport = "7,9,13,19,21,22,23,25,53,79,80-90,106,110,111,119,135,139,143,443,445,465,512-514,554,563,585,636,808,990-995,1025,1027,1080,1098,1099,1352,1433,1521,1525,1935,2049,2082,2083,2086,2087,2401,3260,3306,3128,3389,4444,4848,4899,5000,5432,5800,5900,5901,5984,6000-6009,6379,7001,8000-8010,8042,8080-8090,8181,8443,8447,8686,8880,9008,9043-9045,9060-9062,9080-9090,9111,9443,10001,11443,11444,27017,50000,50013,65301"
defaultthread = 20
defaultverbose = 1
defaultrf = "portbanner.txt"
TLlength = 0
is_exit = False


def usage(p):
    global defaultport
    global defaultsecond
    global defaultthread
    global defaultrf
    
    print "Usage: %s [options]" % p
    print ""
    print "Options"
    print "-h or --help"
    print "-s or --startip=Start IP"
    print "-e or --endip=End IP"
    print "-p or --port=Scan Ports(default %s)" % defaultport
    print "-d or --second=Tcp Timeout(default %d<seconds>)" % defaultsecond
    print "-t or --thread=Scan Thread(default %d)" % defaultthread
    print "-v or --verbose=Verbose Mode(default %d)" % defaultverbose
    print "-w or --resultfile=Write Result File(default %s)" % defaultrf
    print ""
    
    return 0


def handler(signum, frame):
    global is_exit
    is_exit = True
    
    
def getMatch(regex, text):
    res = re.compile(regex, re.I|re.L|re.S|re.M).findall(text)
    #res = re.findall(regex, text)
    return res


def ip2num(ip):
    ip = [int(x) for x in ip.split('.')]
    return ip[0]<<24 | ip[1]<<16 | ip[2]<<8 | ip[3]


def num2ip(num):
    return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24, (num & 0x00ff0000) >> 16, (num & 0x0000ff00) >> 8, num & 0x000000ff)


def gen_ip(ip1, ip2):
    return [num2ip(num) for num in range(ip1, ip2+1)]


def gen_TotalList(ip1, ip2):
    global TotalList
    global portlist
    
    TotalList = []
    IP_A = gen_ip(ip1, ip2)

    for ip in IP_A:
        for port in portlist:
            totalline = []
            totalline.append(ip)
            totalline.append(port)
            TotalList.append(totalline)
    
    random.shuffle(TotalList)

    return len(TotalList)
    

def checkweb(threadid, IP, Port, timeout):
    appinfo = ""
    version = ""
    url = ""
    resp = []
    title = []
    
    try:
        socket.setdefaulttimeout(timeout)
        try:
            url = "http://" + IP + ":" + str(Port)
            rq = urllib2.Request(url)
            rq.add_header("accept-encoding", "gzip, deflate")
            rq.add_header("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
            #rq.get_method = lambda: 'HEAD'
            opener = urllib2.build_opener(RedirectHandler, ErrorHandler)
            req = opener.open(rq)
            
            html = req.read()
            if req.info().has_key('content-encoding') and req.info()['content-encoding'] == 'gzip':
                html = zlib.decompress(html, zlib.MAX_WBITS|32)
            
            regex = "<title.*?>(.*?)</title>"
            title = getMatch(regex, html)

            if len(req.info()) == 0 and len(title) == 0:
                raise Exception("No Banner!")
            if req.info().has_key('server'):
                resp.append(req.info()['server'])
            if req.info().has_key('x-powered-by'):
                resp.append(req.info()['x-powered-by'])
            if len(title) != 0:
                try:
                    resp.append(title[0].decode('utf-8').encode('gbk'))
                except:
                    resp.append(title[0])
        except:
            url = "https://" + IP + ":" + str(Port)
            rq = urllib2.Request(url)
            rq.add_header("accept-encoding", "gzip, deflate")
            rq.add_header("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
            #rq.get_method = lambda: 'HEAD'
            opener = urllib2.build_opener(RedirectHandler, ErrorHandler)
            req = opener.open(rq)
            
            html = req.read()
            if req.info().has_key('content-encoding') and req.info()['content-encoding'] == 'gzip':
                html = zlib.decompress(html, zlib.MAX_WBITS|32)
            
            regex = "<title.*?>(.*?)</title>"
            title = getMatch(regex, html)
            
            if req.info().has_key('server'):
                resp.append(req.info()['server'])
            if req.info().has_key('x-powered-by'):
                resp.append(req.info()['x-powered-by'])
            if len(title) != 0:
                try:
                    resp.append(title[0].decode('utf-8').encode('gbk'))
                except:
                    resp.append(title[0])
        
        if len(resp):
            if len(resp) == 1 and len(title) != 0:
                appinfo = "Title: " + resp[0]
            else:
                if resp[0].find("Lotus-Domino") == 0:
                    version = getdominover(url, timeout)
                if version != "":
                    appinfo = "Server: " + resp[0] + " " + version
                else:
                    appinfo = "Server: " + resp[0]
                if len(resp) == 2 and len(title) != 0:
                    appinfo += "\n|_ Title: " + resp[1]
                elif len(resp) == 2 and len(title) == 0:
                    appinfo += " -- X-Powered-By: " + resp[1]
                elif len(resp) == 3:
                    appinfo += " -- X-Powered-By: " + resp[1] + "\n|_ Title: " + resp[2]
    except:
        s=sys.exc_info()
        #printout = "\nCheck2 function Error " + s[1] + " happened on line " + str(s[2].tb_lineno)
        #sys.stdout.write(printout)
        #sys.stdout.flush()
        #print "\nCheck function Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
        #return ""
    
    return appinfo


#/iNotes/Forms5.nsf,/iNotes/Forms6.nsf,/iNotes/Forms7.nsf,/help/readme.nsf?OpenAbout,/download/filesets/l_LOTUS_SCRIPT.inf,/download/filesets/l_SEARCH.inf
def getdominover(url, timeout):
    version = ""
    
    try:
        socket.setdefaulttimeout(timeout)
        weburl = url + "/download/filesets/n_LOTUS_SCRIPT.inf"
        rq = urllib2.Request(weburl)
        rq.add_header("accept-encoding", "gzip, deflate")
        rq.add_header("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
        opener = urllib2.build_opener(RedirectHandler, ErrorHandler)
        req = opener.open(rq)
        
        html = req.read()
        if req.info().has_key('content-encoding') and req.info()['content-encoding'] == 'gzip':
            html = zlib.decompress(html, zlib.MAX_WBITS|32)
        
        if html.find("Version=") <= 0:
            weburl = url + "/download/filesets/n_SEARCH.inf"
            rq = urllib2.Request(weburl)
            rq.add_header("accept-encoding", "gzip, deflate")
            rq.add_header("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
            opener = urllib2.build_opener(RedirectHandler, ErrorHandler)
            req = opener.open(rq)
            
            html = req.read()
            if req.info().has_key('content-encoding') and req.info()['content-encoding'] == 'gzip':
                html = zlib.decompress(html, zlib.MAX_WBITS|32)
                
        if html.find("Version=") > 0:
            version = "[" + html[html.find("Version=")+len("Version="):].strip() + "]"
    except:
        s=sys.exc_info()
        #printout = "\nCheck2 function Error " + s[1] + " happened on line " + str(s[2].tb_lineno)
        #sys.stdout.write(printout)
        #sys.stdout.flush()
        #print "\nCheck function Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
        #return ""
    
    return version


def check(threadid, IP, Port, timeout):
    status = ""
    data = ""
    errfds = ""
    sock = 0
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IP, Port))
    
        #status = IP + " TCP " + str(Port) + " Open"
        #infds, outfds, errfds = select.select([sock], [], [sock], timeout)
        #if len(infds):
        #    data = sock.recv(1024)
        #    if data != "":
        #        status += ", Banner = " + data.strip()
        if len(data) == 0 and len(errfds) == 0:
            infds, outfds, errfds = select.select([], [sock], [sock], timeout)
            if len(outfds):
                appinfo = checkweb(threadid, IP, Port, timeout)
                
                if appinfo != "":
                    status = IP + " TCP " + str(Port) + " Open"
                    status += ", Banner = " + appinfo
            
    except:
        s=sys.exc_info()
        #printout = "\nCheck2 function Error " + s[1] + " happened on line " + str(s[2].tb_lineno)
        #sys.stdout.write(printout)
        #sys.stdout.flush()
        #print "\nCheck function Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
        #return ""
    
    if sock:
        sock.close()
    
    return status


def threadcode(threadid, length, timeout, verbose):
    global TotalList
    global scannum
    global fw
    global startip
    global endip
    global endipflag
    global ListLine
    global TLlength
    global is_exit
    try:
        while not is_exit:
            l.acquire()
            if scannum >= length:
                l.release()
                break
            elif ListLine >= TLlength:
                endip = startip + (256 * 100)
                if endip > endipflag:
                    endip = endipflag
                TLlength = gen_TotalList(startip, endip)
                startip = endip + 1
                ListLine = 0
            
            IP = TotalList[ListLine][0]
            Port = TotalList[ListLine][1]
            if (ip2num(IP) & 0xff) == 0:
                scannum +=1
                ListLine += 1
                l.release()
                continue
            
            if verbose:    
                printout = "\rThread " + str(threadid) + " scanning " + IP + ":" + str(Port) + ", " + str((scannum*100)/length) + "% finished."
                while len(printout) < 79:
                    printout += " "
                #printout = '{0: <79}'.format(printout)
                sys.stdout.write(printout)
                sys.stdout.flush()
            scannum += 1
            ListLine += 1
            l.release()
                
            appinfo = check(threadid, IP, Port, timeout)
                
            if appinfo != "":
                printout = "\r" + appinfo
                while len(printout) < 79:
                    printout += " "
                #printout = '{0: <79}'.format(printout)
                printout += "\n"
                appinfo += "\n"
                l.acquire()
                if verbose:
                    sys.stdout.write(printout)
                    sys.stdout.flush()
                fw.write(appinfo)
                fw.flush()
                l.release()
            
        printout = "\rThread " + str(threadid) + " End."
        while len(printout) < 79:
            printout += " "
        #printout = '{0: <79}'.format(printout)
        sys.stdout.write(printout)
        sys.stdout.flush()
        
    except:
        s=sys.exc_info()
        #thread = str(threadid)
        #printout = "\rBing Thread " + thread + " End, Error " + s[1] + " happened on line " + str(s[2].tb_lineno)
        #sys.stdout.write(printout)
        #sys.stdout.flush()
        if verbose:
            print "\nThread %d End, Error '%s' happened on line %d" % (threadid, s[1], s[2].tb_lineno)




print "TCPPort Banner Scanner v2.0 (2014-09-29)"
print ""
    
if (len(sys.argv) == 1):
    usage(sys.argv[0])
    sys.exit(1)
shortargs = 'hs:e:p:d:t:v:w:'
longargs = ['help', 'startip=', 'endip=', 'port=', 'second=', 'thread=', 'verbose=', 'resultfile=']
opts,args = getopt.getopt(sys.argv[1:], shortargs, longargs)

if args:
    usage(sys.argv[0])
    sys.exit(1)

paramdict = {'startip': "NULL", 'endip': "NULL", 'port': defaultport, 'second': defaultsecond, 'thread': defaultthread, 'verbose': defaultverbose, 'resultfile': defaultrf}
for opt,val in opts:
    if opt in ('-h', '--help'):
        usage(sys.argv[0])
        sys.exit(1)
    if opt in ('-s', '--startip'):
        paramdict['startip'] = val
        continue
    if opt in ('-e', '--endip'):
        paramdict['endip'] = val
        continue
    if opt in ('-p', '--port'):
        paramdict['port'] = val
        continue
    if opt in ('-d', '--second'):
        paramdict['second'] = int(val)
        continue
    if opt in ('-t', '--thread'):
        paramdict['thread'] = int(val)
        continue
    if opt in ('-v', '--verbose'):
        paramdict['verbose'] = int(val)
        continue
    if opt in ('-w', '--resultfile'):
        paramdict['resultfile'] = val
        continue
    
if paramdict['startip'] == "NULL" or paramdict['endip'] == "NULL":
    usage(sys.argv[0])
    sys.exit(1)

startip = ip2num(paramdict['startip'])
endip = ip2num(paramdict['endip'])
endipflag = ip2num(paramdict['endip'])
if startip > endip:
    usage(sys.argv[0])
    sys.exit(1)

if paramdict['port'] == "":
    usage(sys.argv[0])
    sys.exit(1)
    
if paramdict['second'] <= 0:
    usage(sys.argv[0])
    sys.exit(1)

if paramdict['thread'] <= 0:
    usage(sys.argv[0])
    sys.exit(1)

signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

try:    
    if paramdict['resultfile'] != "NULL":
        fw = open(paramdict['resultfile'], 'a+')
    
    portlist = []
    strportlist = paramdict['port'].split(',')
    
    for port in strportlist:
        if port.find("-") > 0:
            ports = port.split('-')
            for i in range(int(ports[0]), int(ports[1])+1):
                portlist.append(i)
        else:
            portlist.append(int(port))
    
    iplength = endip-startip+1
    length = iplength*len(portlist)
    
    output = paramdict['startip'] + "-" + paramdict['endip'] + "\n"
    fw.write(output)
    fw.flush()
    
    if length < paramdict['thread']:
        paramdict['thread'] = length
        
    childthreads = []
    for i in range(paramdict['thread']):
        t = threading.Thread(target=threadcode, args=(i+1, length, paramdict['second'], paramdict['verbose']))
        t.setDaemon(1)
        t.start()
        childthreads.append(t)
        
    while 1:
        alive = False
        for i in range(paramdict['thread']):
            alive = alive or childthreads[i].isAlive()
            
        if not alive:
            break
        
except:
    s=sys.exc_info()
    print "Error '%s' happened on line %d\n" % (s[1],s[2].tb_lineno)

if fw != 0:
    fw.close()