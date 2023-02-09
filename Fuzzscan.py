import argparse
import logging
import socket
import sys
import ipaddr
import requests
from time import time
from threading import Thread
from bs4 import BeautifulSoup
from queue import Queue
requests.packages.urllib3.disable_warnings()


Ports_web = [80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1118,1888,2008,2020,2100,2375,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018]
Ports_other = [21,22,135,139,445,1433,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017]
Ports = Ports_other + Ports_web
user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"

queue = Queue()


def Fuzzscan(ips):
    # print(ipa)
    ips=ipaddr.IPNetwork(ips)
    # print(ips)
    for ip in ips:
        queue.put(ip)
    threads_list = []
    threads = 100

    for i in range(threads):
        t = Thread(target=scan)
        t.start()
        threads_list.append(t)

    for i in range(threads):
        threads_list[i].join()

def scan():
    ip =queue.get()
    for port in Ports:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.settimeout(0.6)
            s.connect((str(ip), port))

            if port in Ports_other:
                url = str(ip) + ":" + str(port)
                info = "open"

            else:
                protocol = "http" if port not in [443] else "https"
                url = "{0}://{1}:{2}".format(protocol, ip, port)

                url = "{protocol}://{ip}:{port}".format(protocol=protocol, ip=ip, port=port)
                # print(url)

                info = get_web(url)

            if info is None:
                pass
            else:
                sys.stdout.write("%-28s %-30s\n" % (url, info))

            s.close()

        except Exception as e:
            s.close()
            continue

def get_web(url):
    try:
        r = requests.get(url, headers={'UserAgent': user_agent}, timeout=6, verify=False, allow_redirects=True)
        soup = BeautifulSoup(r.content, 'html.parser')

        if soup.text:
            info = soup.title
            return info
        else:
            info = "NO tittle"
            if 'Server' in r.headers:
                info += "\t" + r.headers['Server']
            if 'X-Powered-By' in r.headers:
                info += "\t" + r.headers['X-Powered-By']
                return info

    except Exception as e:
        print(e)
#
def files(file):
    with open (file,'r') as f:
        for line in f.readlines():
            line =line.rstrip()
            queue.put(line)
    thread_list =[]
    threads =500

    for i in range(threads):
        t =Thread(target=scan)
        t.start()
        thread_list.append(t)
    for i in range (threads):
        thread_list[i].join()



if __name__ == '__main__':
    # Fuzzscan("110.242.68.3")

    parser = argparse.ArgumentParser(
        usage='Fuzzscan -h '

    )

    parser.add_argument("-i", dest="ips",
                        help="Use ip  (192.168.0.1/24)")
    parser.add_argument("-f", dest="file",
                        help="Use file url.txt")

    args = parser.parse_args()

    if args.ips is None and args.file is None:
        exit(0)

    if args.ips:
        print('Target: ' + args.ips)
        Fuzzscan(args.ips)

    if args.file:
        files(args.file)
