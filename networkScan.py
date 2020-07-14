#!/usr/bin/python3
import os
import subprocess
import json
import time

def get_ip_network():

    mine = os.popen('ifconfig eth0 | grep "inet 192"').read()
    li = list(filter(lambda a: len(a) > 0, mine.split(" ")))
    ip = [int(i) for i in li[1].split(".")]
    mask = [int(i) for i in li[3].split(".")]
    net = '.'.join([str(s) for s in [ip[0] & mask[0], ip[1] & mask[1], ip[2] & mask[2], ip[3] & mask[3]]])
    mask = ['{0:08b}'.format(s) for s in mask]
    subnet = str(mask[0].count('1') + mask[1].count('1') + mask[2].count('1') + mask[3].count('1'))
    return net + '/' + subnet


def command_output(ip_range):
    
    #command = "nmap -sn -n " + ip_range # Adicionar --max-parallelism 100
    command = ['nmap', '-sn', '-n', ip_range]
    try:
        #sample = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        sample = subprocess.Popen(command, universal_newlines=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        sample.wait()
        data = {'devices': []}
        flag = 0
        IP = ""
        MAC = ""
        vendor = ""
        for line in sample.stdout:
            if "(" in line and "MAC" in line:
                vendor = line.split("(")[1].rstrip()[:-1]
            line = line.split(" ")
            if line[0] == "Nmap":
                if flag == 1:
                    data['devices'].append({
                        'IP': IP,
                        'MAC': MAC,
                        'Vendor': vendor
                    })
                    IP = ""
                    MAC = ""
                    vendor = ""
                flag = 1
                IP = line[4].rstrip()
            elif flag == 1:
                if line[0] == "Host":
                    pass
                elif line[0] == "MAC":
                    MAC = line[2]
                    data['devices'].append({
                        'IP': IP,
                        'MAC': MAC,
                        'Vendor': vendor
                    })
                    IP = ""
                    MAC = ""
                    vendor = ""
                    flag = 0
        #json.dump(data, file, indent=4, sort_keys=True)
    finally:
        sample.kill()
    return data


def networkScanner(round):
    ip = get_ip_network()
    data = []
    for a in range(0,round):
        data.append(command_output(ip)) 
        time.sleep(10)
    
    big = max(data, key = lambda x : len(x['devices']))

    with open("./hosts/out.json", 'w') as file:
        json.dump(big,file, indent=4, sort_keys=True)

    return big


if __name__ == "__main__":
    
    networkScanner()
