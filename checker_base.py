__author__ = 'daniilre'
import os
import re
import sys
import time
import subprocess
import http.client
import threading
import telnetlib
import requests
import warnings
import datetime
import inspect
from math import ceil
from ftplib import FTP
from StringIO import StringIO
from multiprocessing.pool import ThreadPool
from multiprocessing import Manager, Process
import socket
import struct
import socks
import pycurl
import chardet
import random
import uuid
import re
import urllib2
from urlparse import urljoin
from functools import partial

default_socket = socket.socket
from ping import do_one as ping

try:
    # python 3
    from urllib.parse import urlencode
except ImportError:
    # python 2
    from urllib import urlencode

MAX_PROC = 50  # Number of threads

TIMEOUT_FI = 15  # Timeout for proxy checking (in seconds) for first iteration
TIMEOUT = 10  # Timeout for proxy checking (in seconds)

#  Suppressing SSL certificate warning
warnings.filterwarnings("ignore")

HAPROXY_FILE = "./haproxy-https.cfg"

global used_user_agents_list
used_user_agents_list = []
global user_agents_list
user_agents_list = []


def ftp_upload(ftp, f):
    ext = os.path.splitext(f)[1]
    if ext in (".txt", ".htm", ".html"):
        ftp.storlines("STOR " + f, open(f))
    else:
        ftp.storbinary("STOR " + f, open(f, "rb"), 1024)


def ensure_dir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)


def save_file(name, text):
    if name:
        if text:
            with open(name, 'w') as f:
                encoding = chardet.detect(text)
                if encoding['encoding'] != 'utf-8':
                    f.write(text.encode('utf-8'))
                else:
                    f.write(text)


def is_empty_file(path):
    return (not os.path.isfile(path)) and os.stat(path).st_size == 0


def load_user_agents(uafile=None, user_agents=None, used_user_agents=[], mobile_version=False):
    """
    uafile : string
        path to text file of user agents, one per line
    """
    uas = []
    if uafile is not None:
        with open(uafile, 'rb') as uaf:
            for ua in uaf.readlines():
                if ua and ua not in used_user_agents:
                    if not mobile_version and 'mobile' in ua.lower():
                        continue
                    else:
                        uas.append(ua.strip()[1:-1 - 1])
            random.shuffle(uas)
            return uas
    elif user_agents is not None:
        for ua in user_agents:
            if ua and ua not in used_user_agents:
                if not mobile_version and 'mobile' in ua.lower():
                    continue
                else:
                    uas.append(ua.strip()[1:-1 - 1])
        random.shuffle(uas)
        return uas


def get_user_agent(used_user_agents=None):
    global used_user_agents_list
    global user_agents_list
    if used_user_agents is None:
        used_user_agents = []
    # load the user agents, in random order
    user_agents = load_user_agents(user_agents=user_agents_list, used_user_agents=used_user_agents)
    ua = random.choice(user_agents)  # select a random user agent
    used_user_agents.append(ua)
    return ua, used_user_agents


def get(protocol, host, port, timeout, url='http://www.bing.com'):
    try:
        buff = StringIO()
        global used_user_agents_list
        def_head = ['Accept-Language: en-US,en;q=0.5',
                    'Accept-Encoding: gzip,deflate',
                    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Connection: keep-alive',
                    'Cache-Control: no-cache']
        ua, used_user_agents_list = get_user_agent(used_user_agents=used_user_agents_list)
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.WRITEDATA, buff)
        c.setopt(pycurl.NOSIGNAL, True)
        c.setopt(pycurl.HTTPHEADER, def_head)
        c.setopt(pycurl.CONNECTTIMEOUT, timeout)
        c.setopt(pycurl.TIMEOUT, timeout)
        c.setopt(pycurl.FOLLOWLOCATION, True)
        c.setopt(pycurl.MAXREDIRS, 3)
        c.setopt(pycurl.USERAGENT, ua)
        c.setopt(pycurl.REFERER, 'http://www.google.com/')
        c.setopt(pycurl.AUTOREFERER, True)
        c.setopt(pycurl.SSL_VERIFYPEER, False)
        c.setopt(pycurl.ENCODING, "gzip,deflate")
        c.setopt(pycurl.VERBOSE, False)
        if protocol in ["usahttp", "https", "http"]:
            c.setopt(c.PROXY, "https://" + ":".join([host, port]))
        elif protocol in ["socks", "socks", "socks5"]:
            c.setopt(c.PROXY, "socks5h://" + ":".join([host, port]))
        c.perform()
        stat = c.getinfo(pycurl.HTTP_CODE) in (200, 301)
        if stat == False:
            c.close()
            return buff.getvalue(), stat
        if protocol in ["https", "http", "usa"]:
            c.setopt(c.URL, 'http://www.bing.com/search?q=google.com')
            c.perform()
        stat = c.getinfo(pycurl.HTTP_CODE) in (200, 301)
        c.close()
        return buff.getvalue(), stat
    except pycurl.error as ex:
        return '', False
    except Exception as ex:
        return '', False


def get1(protocol, host, port, timeout, url='https://gondorland.com/ipcheck.php'):
    try:
        buff = StringIO()
        global used_user_agents_list
        def_head = ['Accept-Language: en-US,en;q=0.5',
                    'Accept-Encoding: gzip,deflate',
                    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Connection: keep-alive',
                    'Cache-Control: no-cache']
        ua, used_user_agents_list = get_user_agent(used_user_agents=used_user_agents_list)
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.WRITEDATA, buff)
        c.setopt(pycurl.NOSIGNAL, True)
        c.setopt(pycurl.HTTPHEADER, def_head)
        c.setopt(pycurl.CONNECTTIMEOUT, 30)
        c.setopt(pycurl.TIMEOUT, 30)
        c.setopt(pycurl.FOLLOWLOCATION, True)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.USERAGENT, ua)
        c.setopt(pycurl.AUTOREFERER, True)
        c.setopt(pycurl.SSL_VERIFYPEER, False)
        c.setopt(pycurl.ENCODING, "gzip,deflate")
        c.setopt(pycurl.VERBOSE, False)
        if protocol in ["usahttp", "https", "http"]:
            c.setopt(c.PROXY, "https://" + ":".join([host, port]))
        elif protocol in ["socks", "socks", "socks5"]:
            c.setopt(c.PROXY, "socks5h://" + ":".join([host, port]))
        c.perform()
        stat = c.getinfo(pycurl.HTTP_CODE) == 200 or c.getinfo(pycurl.HTTP_CODE) == 301
        if stat == False:
            c.close()
            return buff.getvalue(), stat
        if protocol in ["https", "http", "usahttp"]:
            url = 'https://gondorland.com/ipcheck.php'
            post_data = {'search': 'verify my proxy'}
            # Form data must be provided already urlencoded.
            postfields = urlencode(post_data)
            c.setopt(c.URL, url)
            c.setopt(pycurl.POST, True)
            c.setopt(pycurl.POSTFIELDS, postfields)
            c.perform()
        stat = c.getinfo(pycurl.HTTP_CODE) == 200 or c.getinfo(pycurl.HTTP_CODE) == 301
        c.close()
        return buff.getvalue(), stat
    except pycurl.error as ex:
        # print str(ex)
        return '', False
    except Exception as ex:
        # print str(ex)
        return '', False


def save_bing_response(content, protocol, host, port):
    try:
        tmp_str = protocol + '_' + str(host) + '_' + str(port)
        tmp_str = tmp_str.replace('.', '_')
        save_path = os.path.abspath(__file__).replace(os.sep + os.path.basename(__file__), '')
        save_path = os.path.join(save_path, 'bing_response_files')
        filename = os.path.join(save_path,
                                tmp_str + '_' + str(datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")) + '.html')
        ensure_dir(filename)
        save_file(filename, content)
    except Exception as ex:
        print ('Error: ' + str(ex))


def visit_verifier(protocol, host, port, timeout):
    if protocol in ["https", "http", "usahttp", "socks", "usa", "europe", "asia", "socks"]:
        try:
            # print 'Going search Bing.com == IP: '+str(host) + '  Port: ' + str(port)
            content, is_status_ok = get1(protocol, host, port, timeout)
            # save_bing_response(content, protocol, host, port)
            if protocol in ["https", "http", "usahttp"]:
                # http://www.bing.com/search?q=google.com
                if "valid" in content:
                    # save_bing_response(content, protocol, host, port)
                    return True
                else:
                    return False
            else:
                if "name=\"search\"" in content:
                    return True
                else:
                    return False
        except pycurl.error as ex:
            # print "Timeout: Proxy could not connect."
            return False
    return False


def visit_bing(protocol, host, port, timeout):
    bing_url = 'http://www.bing.com/'
    if protocol in ["https", "http", "usahttp", "socks", "socks5", "socks"]:
        try:
            # print 'Going search Bing.com == IP: '+str(host) + '  Port: ' + str(port)
            content, is_status_ok = get(protocol, host, port, timeout)
            # save_bing_response(content, protocol, host, port)
            if protocol in ["https", "http", "usahttp"]:
                # http://www.bing.com/search?q=google.com
                if "<title>google.com - Bing</title>" in content and "<strong>google.com</strong></a>" in content:
                    # save_bing_response(content, protocol, host, port)
                    return True
                else:
                    return False
            else:
                if is_status_ok and "Bing" in content and "name=\"q\"" in content and "<form" in content:
                    return True
                else:
                    return False
        except pycurl.error as ex:
            # print "Timeout: Proxy could not connect."
            return False
    return False


def verify_proxy(protocol, host, port, timeout):
    if visit_bing(protocol, host, port, timeout):
        return True
    return False


def check_proxy(proxy, protocol="https", check_address="https://gondorland.com/ipcheck.php", check_for="host",
                timeout=TIMEOUT_FI, command='check'):
    """
    Check proxy validity
    :param host: proxy host
    :param port: proxy port
    :param protocol: proxt protocol (like https, http, socks)
    :param check_address: Address to test proxy with
    :return: True if proxy is valid. False if proxt is invalid
    """
    if protocol == "socks":
        protocol = "socks5"
    if protocol == "socks5":
        check_address = check_address.replace("https", "http")
    if len(proxy) != 2:
        return (False, proxy)
    host, port = proxy
    if check_for == "host":
        check_for = host
    err = ""
    r = None
    recheck = False
    if command == 'recheck':
        recheck = True
    else:
        recheck = False
    if not port.isdigit() or not "." in host or " " in host.strip():
        return (False, False)
    try:
        socket.setdefaulttimeout(timeout)
        proxies = {
            "https": "%s://%s:%s" % (protocol, host, port)
        }
        if protocol in ("socks5", "smtpsocks"):
            stat = False
            if protocol == "socks5":
                stat = check_port_25_socks5(host, port, timeout)
            elif protocol == "smtpsocks":
                if not is_good_proxy(str(host + ':' + port), timeout):
                    stat = False
                else:
                    resp = do_telnet(host, "25", timeout)
                    # tel = telnetlib.Telnet()
                    # tel.open(str(host), "25", timeout)
                    # resp = tel.read_until("\n", timeout)
                    stat = ("220" in resp or "200" in resp)
                    if stat and socket.gethostbyname(socket.gethostbyaddr(host)[0]) != host:
                        stat = False

        elif protocol == "smtp":
            if protocol == "smtpsocks":
                conn_resp = "220"
            else:
                write_text = "CONNECT mail.glocksoft.com:25 HTTP/1.0\r\n\r\n"
                read_until_text = "\r\n"
                conn_resp = do_telnet(host, port, timeout, write_text, read_until_text)

            stat = False
            if not is_good_proxy(str(host + ':' + port), timeout):
                stat = False
            else:
                resp = do_telnet(host, "25", timeout)
                stat = ("220" in resp or "200" in resp) and (
                            "Connection established" in conn_resp or "220" in conn_resp)
                if stat and socket.gethostbyname(socket.gethostbyaddr(host)[0]) != host:
                    stat = False
                else:
                    stat = True
        else:
            stat = False
            if is_good_proxy(str(proxy[0] + ':' + proxy[1]), timeout):
                stat = True
            # elif recheck:
            #    stat = True
            # elif visit_verifier(protocol, host, port, timeout):
            #     stat = True
            else:
                stat = False
    except requests.exceptions.Timeout:
        print ("[%i] Timeout at %s for %s" % (os.getpid(), time.time(), str(proxy)))
        stat = False
    except Exception as e:
        import traceback

        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        err = traceback.format_exc()
        stat = False

    if stat:
        print ("[%s pid%i] %s (port %s) is %s" % (
            threading.currentThread().getName(), os.getpid(), proxy[0], proxy[1], "valid" if stat else "invalid"), err)

    if not stat:
        return (False, False)
    else:
        return (True, proxy)


def is_bad_sock_proxy(pip, host):
    try:
        proxy_handler = urllib2.ProxyHandler({'https': pip})
        opener = urllib2.build_opener(proxy_handler)
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib2.install_opener(opener)
        req = urllib2.Request('https://gondorland.com/ipcheck.php')  # change the url address here
        response = urllib2.urlopen(req)
        if not host in response.read():
            print (pip, 'error')
            return False
    except urllib2.HTTPError as e:
        print (pip, ':Error code: ', e.code)
        return False
    except Exception as detail:

        print (pip, ":ERROR:", detail)
        return False
    return True


def is_good_proxy(pip, timeout):
    try:
        proxy_handler = urllib2.ProxyHandler({'https': pip})
        opener = urllib2.build_opener(proxy_handler)
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib2.install_opener(opener)
        req = urllib2.Request('https://gondorland.com/ipcheck.php')  # change the url address here
        sock = urllib2.urlopen(req, timeout=timeout)
    except urllib2.HTTPError as e:
        print (pip, ':Error code: ', e.code)
        return False
    except Exception as detail:
        print (pip, ":ERROR:", detail)
        return False
    return True


def do_telnet(host, port, timeout, write_text=None, read_until_text="\n"):
    tel = telnetlib.Telnet()
    tel.open(str(host), int(port), timeout)
    if write_text is not None:
        tel.write(write_text)
    resp = tel.read_until(read_until_text, timeout)
    tel.close()
    return resp

def check_port_25_socks5(host, port, timeout):
    is_port_25_open = False
    client_socket = socks.socksocket()  # Same API as socket.socket in the standard lib
    client_socket.settimeout(timeout)
    client_socket.set_proxy(socks.SOCKS5, addr=host, port=int(port))  # Set SOCKS5 proxy

    # Can be treated identical to a regular socket object
    client_socket.connect(("mail.glocksoft.com", 25))
    recv_resp = client_socket.recv(1024)
    if recv_resp[:3] != '220':
        is_port_25_open = False
    else:
        # Send HELO command and print server response.
        hello_command = 'EHLO localhost\r\n'
        client_socket.send(hello_command)
        recv1 = client_socket.recv(1024)
        if recv1[:3] != '250':
            is_port_25_open = False
        else:
            is_port_25_open = True
    client_socket.shutdown(2)
    client_socket.close()
    return is_port_25_open

def get_proxy_from_text(text):
    if "<br>" in text:
        splitter = "<br>"
    else:
        splitter = "\n"
    return [addr.strip().split(" ") if ":" not in addr else addr.strip().split(":") for addr in text.split(splitter) if
            "." in addr]


def submit_proxy(filename, proxies, mode="replace", protocol="https", namespace=None, tor=False):
    if not namespace:
        namespace = protocol
    with open(filename) as f:
        config = f.read()
    with open(filename, 'w+') as f:
        config_split = config.split("#" + namespace + "\n")
        config = config_split[0] + "#" + namespace + "\n"
        f.write(config)
        pattern = r"(server|pysmtp|pyhttps|[a-z0-9]+|check|\s+)"
        oldproxies = map(lambda s: re.sub(pattern=pattern, repl="", string=s), config_split[1].strip().split("\n"))
        oldproxies = set(oldproxies)
        oldproxiesbackup = oldproxies

        print("oldproxies has length", len(oldproxies))
        print("current proxies has length", len(proxies))

        for idx, proxy in enumerate(proxies, start=1):
            if proxy[0] == True:
                if mode == "add":
                    proxytext = "%s:%s" % (proxy[1][0], proxy[1][1])
                    """"
                    if proxytext in oldproxies:
                                continue
                            else:
                                oldproxies.add(proxytext)
                    """

                    if tor:
                        if not re.search(r'%s\s+tcp dpt:%s' % (proxy[1][0], str(proxy[1][1])),
                                         subprocess.check_output("iptables -n -t nat -L".split())):
                            cmd = "iptables -t nat -A OUTPUT -p tcp -d %s --dport %s --syn -j REDIRECT --to-ports 9981" % (
                                proxy[1][0], str(proxy[1][1]))
                            subprocess.check_output(cmd.split())
                    if (check_proxy_not_empty(proxy[1][0])):
                        f.write("        server py%s%s %s:%s check\n" % (
                        protocol, idx, extract_ip_adress(proxy[1][0]), proxy[1][1]))
        if mode == "add" and len(config_split) > 1:
            """
                for proxy in oldproxiesbackup:
                    if(check_proxy_not_empty(proxy)):
                        ip_port = proxy
                        proxy_split = proxy.split(":")
                        if(len(proxy_split) > 1):
                            ip_port = extract_ip_adress(proxy) + ":" + proxy.split(":")[1]
                        f.write("        server py%s %s check\n" % (protocol, ip_port))
            """
        else:
            if len(config_split) >= 2:
                lines = config_split[1].split("\n")
                start = 0
                for n, line in enumerate(lines):
                    if "#" in line:
                        start = n
                        break
                if start:
                    f.write("\n".join(lines[start:]))
        f.close()
        if protocol == "smtp":
            (host, user, password, filename) = ("216.155.147.219", "ftp", "mordor398", "http_connect.txt")
            with open(filename, 'w') as f:
                for proxy in oldproxies:
                    f.write(proxy + "\n")

            # ftp = FTP(host, timeout=30)
            # ftp.login(user, password)
            # enable TLS
            # ftp.auth()
            # ftp.prot_p()
            # ftp_upload(ftp=ftp, f=filename)


def get_proxy_from_ftp(host, user, password, files):
    """
    Get proxt from ftp server
    :param host: FTP host
    :param user: FTP user
    :param password: FTP password
    :param files: file pathes with proxies addresses
    :return:
    """
    ftp = FTP(host, timeout=30)
    ftp.login(user, password)
    r = StringIO()
    proxies = []
    for file in files:
        a = ftp.retrbinary("RETR " + file, r.write)
        proxies += get_proxy_from_text(r.getvalue())
    return proxies


def get_proxy_from_http(url):
    r = requests.get(url, timeout=30, verify=False)
    return get_proxy_from_text(r.text)


def get_proxy_from_txt(file):
    with open(file) as f:
        return get_proxy_from_text(f.read())


def load_proxies_from_cfg(cfg, namespace=None):
    """
    Load proxies from configuration file (e.g. haproxy_https.conf)
    :param cfg: path to config file
    :return:
    """
    proxies = []
    with open(cfg) as f:
        start_parse = False
        for line in f.readlines():
            if not start_parse:
                if namespace and "#" + namespace in line:
                    start_parse = True
                elif not namespace and ("#https" in line or "#socks" in line):
                    start_parse = True
                continue
            if "#" in line and start_parse:
                break
            rows = line.strip().split()
            if len(rows) == 4:
                ip_and_port = rows[2].split(":")
                ip_and_port[0] = extract_ip_adress(ip_and_port[0])
                proxies.append(ip_and_port)
    return proxies


def start_proccess(proxies):
    print ("[pid %i] Started process" % os.getpid())
    for proxy in proxies:
        res = check_proxy(proxy)
        if res[0]:
            valid_proxy.append(proxy[1])


def start_checker(haproxy, ctl, command, protocol, ftp_list, http_list, file_list, max_proc):
    global user_agents_list
    # load the user agents
    user_agents_list = load_user_agents(uafile='user_agents.txt')
    dnull = open(os.devnull, 'wb')
    valid_proxy = []
    proxies = []
    counter = 0
    no_check = "nocheck" in sys.argv
    recheck = False
    check_proxy_x = partial(check_proxy, protocol=protocol)

    if command == "file":
        proxies = get_proxy_from_txt("list.txt")
    if command == "rdump":
        import hashlib
        proxies = [[True, proxy] for proxy in get_proxy_from_http(sys.argv[3])]
        submit_proxy(haproxy, proxies, "replace", protocol, hashlib.md5(sys.argv[3]).hexdigest()[-5:])
        subprocess.call(ctl.split(" "), stdout=dnull, stderr=dnull)
        return 0
    elif command in ("check", "dump"):
        print ("Getting ftp sources")
        for ftp_source in ftp_list:
            try:
                proxies += get_proxy_from_ftp(*ftp_source)
            except:
                print ("FTP SOURCE", ftp_source, "is broken")
                continue
        print ("Getting url sources")
        for url_source in http_list:
            try:
                proxies += get_proxy_from_http(url_source)
            except:
                print ("HTTP SOURCE", url_source, "is broken")
                continue
        print ("Getting file sources")
        for file_source in file_list:
            proxies += get_proxy_from_txt(file_source)
    else:
        recheck = True

    # elif command == "remote":
    #     ssh = paramiko.SSHClient()
    #     ssh.load_host_keys(os.path.expanduser(os.path.join("/root/", ".ssh", "known_hosts")))
    #     ssh.connect(REMOTE_ADDR, username=REMOTE_USR, password=REMOTE_PASS)
    #     sftp = ssh.open_sftp()
    #     sftp.get(REMOTE_FILE, "/etc/haproxy/tempconf.txt")
    #     sftp.close()
    #     ssh.close()
    #     proxies += load_proxies_from_cfg("/etc/haproxy/tempconf.txt", "scrap")
    if not command == "dump":
        proxies += load_proxies_from_cfg(haproxy)
    else:
        submit_proxy(haproxy, map(lambda p: [True, p], proxies), "replace")
        if ctl:
            subprocess.call(ctl.split(" "), stdout=dnull, stderr=dnull)
        return 1

    if no_check:
        print ("[pid watcher] Writing to without check", haproxy)
        submit_proxy(haproxy, map(lambda p: [True, p], proxies), protocol=protocol + "r", mode="replace")
        if ctl:
            subprocess.call(ctl.split(" "), stdout=dnull, stderr=dnull)
        return 1

    namespaces = [protocol]
    # print namespaces
    if recheck:
        check_proxy_x = partial(check_proxy_x, timeout=30)
        check_proxy_x = partial(check_proxy_x, command=command)
        namespaces.append("scrap")

    for ns in namespaces:
        if recheck:
            proxies = []

        print ("I have %i proxies before loading cfg file" % (len(proxies)))
        proxies += load_proxies_from_cfg(haproxy, ns)
        print ("I have %i proxies after loading cfg file" % (len(proxies)))
        proxies = f5(proxies)
        print ("I have %i proxies after f5 funciton" % (len(proxies)))
        proxies = proxies[:100000000]

        if not proxies:
            continue

        if len(proxies) < max_proc:
            max_proc = len(proxies)

        threads = []
        print ("[pid master] Starting %i threads. Will check %i proxies" % (max_proc, len(proxies)))
        offset = 0
        pcount = len(proxies)

        p = ThreadPool(max_proc)  # , maxtasksperchild=2)
        valid_proxy = p.map(check_proxy_x, proxies)  # , chunksize=100) # chunksize uncommented
        del proxies

        print ("[pid watcher] Writing to ", haproxy, "@%s" % ns)
        if command in ("check", "recheck"):
            submit_proxy(haproxy, valid_proxy, "add", tor=False, protocol=ns, namespace=ns)
        else:
            submit_proxy(haproxy, valid_proxy, "replace", tor=False, protocol=ns, namespace=ns)

        print ("[pid master] VALID: ", len(filter(lambda x: x[0] == True, valid_proxy)))
        if ctl:
            subprocess.call(ctl.split(" "), stdout=dnull, stderr=dnull)
        del valid_proxy
        p.close()
        p.terminate()


def f5(seq, idfun=None):
    # order preserving
    if idfun is None:
        def idfun(x): return "".join(x)
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        # in old Python versions:
        # if seen.has_key(marker)
        # but in new ones:
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result


def check_proxy_not_empty(proxy):
    return proxy.strip()


def extract_ip_adress(proxy):
    bytePattern = "([01]?\d\d?|2[0-4]\d|25[0-5])"
    regObj = re.compile("\.".join([bytePattern] * 4))
    if regObj.search(proxy) == None:
        return proxy
    return regObj.search(proxy).group(0)


class CheckerThread(Process):
    def __init__(self, task_queue, result_queue, checker):
        Process.__init__(self)
        self.checker = checker
        self.task_queue = task_queue
        self.result_queue = result_queue

    def stop(self):
        self.stop = True

    def run(self):
        while True:
            next_task = self.task_queue.get()

            if next_task is None:
                # Poison pill means shutdown
                print ('%s: Exiting' % self.name)
                self.task_queue.task_done()
                break
            self.result_queue.put(self.checker(next_task))

        return


if __name__ == "__main__":
    valid_proxy = []
    m = Manager()
    counter = m.Value(0)




