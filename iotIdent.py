#!/usr/bin/python3
import os
import json


def open_files():

    with open("MAC_VENDORS/known.txt", 'r') as f1, open("MAC_VENDORS/unknown.txt", 'r') as f2:
        content = f1.readlines()
        content = [x.strip() for x in content]
        content2 = f2.readlines()
        content2 = [x.strip() for x in content2]
        f = [content, content2]
    return f


def open_file():

    with open('./hosts/out.json') as f:
        data = f.read()
    obj = json.loads(data)
    out = []
    for data in obj['devices']:
        if data['Vendor'] != "":
            out.append([data['IP'], data['MAC'], data['Vendor']])
    return out
   

def lists_compare(a, b):

    output_list = []
    for host in b:
        if host[2] in a[0]:
            output_list.append(host)
    return [a[:-1] for a in output_list]


def identify_router():

    route = os.popen(" ip r | grep default | grep eth0").read()
    ip_route = list(filter(lambda a: len(a) > 0, route.split(" ")))
    return ip_route[2]


def iotIdentifier():

    vendors = open_files()
    devices = open_file()
    router = identify_router()
    router = list(filter(lambda a: router == a[0], devices))
    router = [router[0][0], router[0][1]]
    lis = lists_compare(vendors, devices)
    with open("./hosts/hosts.txt", "w") as f:
        for device in lis:
            f.write(" ".join(device) + " -\n")
        f.write(" ".join(router) + " -\n")


if __name__ == "__main__":
    
    iotIdentifier()
