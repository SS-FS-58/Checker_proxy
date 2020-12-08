from checker_base import start_checker
import sys
from settings import *

if __name__ == "__main__":
    if sys.argv[1] == "usa":
        start_checker(HTTP2_HAPROXY_FILE, HTTP2_CTL_COMMAND, sys.argv[2], "http2",
                      HTTP_FTP_LIST, HTTP_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "https":
        start_checker(HTTP_HAPROXY_FILE, HTTP_CTL_COMMAND, sys.argv[2], "https",
                      HTTP_FTP_LIST, HTTP_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "europe":
        start_checker(EUROPE_HAPROXY_FILE, EUROPE_CTL_COMMAND, sys.argv[2], "europe",
                      HTTP_FTP_LIST, EUROPE_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "asia":
        start_checker(ASIA_HAPROXY_FILE, ASIA_CTL_COMMAND, sys.argv[2], "asia",
                      HTTP_FTP_LIST, EUROPE_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "smtp":
        start_checker(SMTP_HAPROXY_FILE, SMTP_CTL_COMMAND, sys.argv[2], "smtp",
                      SMTP_FTP_LIST, SMTP_HTTP_LIST, SMTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "smtpsocks":
        start_checker(SMTPSOCKS_HAPROXY_FILE, SMTPSOCKS_CTL_COMMAND, sys.argv[2], "smtpsocks",
                      HTTP_FTP_LIST, SOCKS_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "socks":
        start_checker(SOCKS_HAPROXY_FILE, SOCKS_CTL_COMMAND, sys.argv[2], "socks",
                      HTTP_FTP_LIST, HTTP_HTTP_LIST, HTTP_FILE_SOURCES, MAX_PROC)
    elif sys.argv[1] == "usahttp":
        start_checker(USAHTTP_HAPROXY_FILE, USAHTTP_CTL_COMMAND, sys.argv[2], "usahttp",
                      USAHTTP_FTP_LIST,USAHTTP_HTTP_LIST, USAHTTP_FILE_SOURCES, MAX_PROC)











