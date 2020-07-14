#!/usr/bin/python3.7

from collections import Counter
from scapy.all import *
import json

# Create Global Variables
packet_counts = Counter()
devices = []
data = {}
flag = 0
blankData = {}


# Define Custom Action function
def custom_action(packet):
    global data
    pkt = packet[0][1]
    if pkt.src in devices or pkt.dst in devices:
        # TX
        if pkt.src in devices:
            key = pkt.src
            if pkt.dst in [a['Outsider'] for a in data[key]['Outsiders']]:
                for a in data[key]['Outsiders']:
                    if a['Outsider'] == pkt.dst:
                        a['Quantity'] += 1
            else:
                data[key]['Outsiders'].append({"Outsider": pkt.dst, "Quantity": 1})

            data[key]['Debits']['TX']['Number'] += 1
            data[key]['Debits']['TX']['Size'] += len(packet)


        # RX  
        else:
            key = pkt.dst
            if pkt.src in [a['Outsider'] for a in data[key]['Outsiders']]:

                for a in data[key]['Outsiders']:
                    if a['Outsider'] == pkt.src:
                        a['Quantity'] += 1
            else:
                data[key]['Outsiders'].append({"Outsider": pkt.src, "Quantity": 1})

            data[key]['Debits']['RX']['Number'] += 1
            data[key]['Debits']['RX']['Size'] += len(packet)

        # Tranform protocol value in string
        proto_field = pkt.get_field('proto')
        protocol = proto_field.i2s[pkt.proto]

        if protocol in [a['Protocol'] for a in data[key]['Protocols']]:
            for a in data[key]['Protocols']:
                if a['Protocol'] == protocol:
                    a['Quantity'] += 1
        else:
            data[key]['Protocols'].append({'Protocol': protocol, 'Quantity': 1})

        data[key]['Packets'] += 1


def sniffer(interface):
    # Setup sniff, filtering for IP traffic
    sniff(iface=interface, filter="ip", prn=custom_action, stop_filter=stop)


def getTargets(file):
    for line in file.readlines():
        line = line.split(" ")
        devices.append([line[0], line[1]])


def counterTraffic(interface):
    with open("./hosts/hosts.txt", 'r') as hostsFile:
        getTargets(hostsFile)
    global devices, data, blankData
    devices = [device[0] for device in devices]
    devices = devices[:-1]
    for device in devices:
        data[device] = {
            "Packets": 0,
            # "Connections" : [],
            "Debits": {
                "TX": {
                    "Number": 0,
                    "Size": 0
                },
                "RX": {
                    "Number": 0,
                    "Size": 0
                }
            },
            "Protocols": [],
            "Outsiders": []
        }
    blankData = data
    sniffer(interface)
    # print(json.dumps(data,sort_keys=True, indent=4))


def resetData():
    global data, blankData
    data = blankData


def write_data_to_file():
    global data
    with open("counters/tmp/counter.json", 'w') as output:
        json.dump(data, output, indent=4)


def stop(p):
    global flag
    if flag == 1:
        return True
    else:
        return False


def counter_flag():
    global flag
    flag = 1


if __name__ == "__main__":
    counterTraffic("eth0")
