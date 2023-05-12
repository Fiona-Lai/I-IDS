#!/usr/bin/env python
# encoding: utf-8
from scapy.all import *
from app import app
import threading
import sys
import os
from config import *
import config
import shutil

# 获取网卡名称
def get_ifaces():
    ifaces_list = os.popen('ifconfig').read().split('\n\n')
    ifaces_list = [i for i in ifaces_list if i]
    iface_list = list()
    for ifaces in ifaces_list:
        iface = ifaces.split('\n')[0].split()[0].strip()
        ip = ifaces.split('\n')[1].split()[1].split(':')[-1].strip()
        mac = ifaces.split('\n')[0].split()[-1].strip()
        receive = ifaces.split('\n')[-1].split()[1][1:] + ifaces.split('\n')[-1].split()[2][:-1]
        send = ifaces.split('\n')[-1].split()[-2][1:] + ifaces.split('\n')[-1].split()[-1][:-1]
        iface_list.append(
            {'iface': iface, 'ip': ip, 'mac': mac.encode('utf-8').decode('utf-8'), 'receive': receive, 'send': send})
    return iface_list


def dealwith():
    print('开始抓包')
    iface = str(get_ifaces())
    # 下面的iface是电脑网卡的名称 count是捕获报文的数目
    dpkt = sniff(iface='eth0', count=500)
    print('抓包成功')
    cur_dir = os.getcwd()  # 当前路径
    print(cur_dir)
    ch_dir = os.path.join(cur_dir,"pcaps/capture.pcap")
    print(ch_dir)
    # filepath = app.config['UPLOAD_FOLDER']
    # os.chdir(filepath)
    wrpcap(ch_dir, dpkt)  # 保存在utils下，与capture.py同目录
    # file.save(os.path.join(filepath, 'capture.pcap'))
    # dpkt.save(os.path.join(filepath, 'capture.pcap'))
    # generated_pcap_file = wrpcap("capture.pcap", dpkt)


    # app_dir = os.path.dirname(cur_dir)  # app的目录路径
    # parent_dir = os.path.dirname(app_dir)  # app的上一级目录Pcap-Analyser
    # pcap_dir = os.path.join(parent_dir,'pcaps')  # join函数合并路径Pcap-Analyser/pcaps
    # print(pcap_dir)
    # pcap_file = os.path.join(pcap_dir,'capture.pcap')  # capture.pcap的绝对路径
    # print(pcap_file)
    # shutil.copyfile(generated_pcap_file,pcap_file)
      # os.path.chdir('..\\pcaps\\capture.pcap')
    print('所抓的包已经保存')

    pcks = rdpcap('capture.pcap')
    print('开始解析pcap包')

    # 输出重定向：将在控制台的输出重定向到txt文本文件中
    output = sys.stdout
    outputfile = open('capture.txt', 'w')
    sys.stdout = outputfile

    zArp = 0
    zIcmp = 0
    ipNum = set()

    for p in pcks:
        status1 = p.payload.name  # 可能是ARP的报文
        status2 = p.payload.payload.name  # 可能是TCP报文 也可能是ICMP的报文

        # p.show() 输出报文，在符合的情况下
        if status1 == 'IP':
            ipNum.add(p.payload.src)  # 将ip报文的源地址，和目的地址存在set集合里面（set去重）
            ipNum.add(p.payload.dst)
            p.show()
            print('')
        else:
            if status1 == 'ARP':
                p.show()
                print('')
                zArp += 1

            if status2 == 'ICMP':
                p.show()
                print('')
                zIcmp += 1

    print('IP：' + str(len(ipNum)) + ' ARP：' + str(zArp) + ' ICMP：' + str(zIcmp))  # 报文数量的输出

    outputfile.close()
    sys.stdout = output  # 恢复到控制台输出

    print('输出结束')
    print(dpkt)


def capture():
    get_ifaces()
    dealwith()  # 运行报文捕获函数

    # return


if __name__ == "__main__":
    capture()
 
 
