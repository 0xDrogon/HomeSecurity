#!/usr/bin/python3
import subprocess
import json
import os
from datetime import datetime
from alertUser import sendEmail, sendSMS


# Represents a device in the network (IP Address and Ports/Services)
class Device: 
    def __init__(self, ip, services):
        self.ip = ip
        self.services = services


# Retrieves the newest file from the specified directory
def newestFileFromDir(path):

    files = os.listdir(path)
    if not files:
        return None
    paths = [os.path.join(path, basename) for basename in files]
    return max(paths, key=os.path.getctime)


# Retrieves IP addresses from the hosts file
def getIPsFromFile():
    
    with open("./hosts/hosts.txt", 'r') as hostsFile: # Opens file with hosts to scan
        content = hostsFile.readlines()
    content = [x.split(' ')[0] for x in content]
    content.pop() #error here!
    out = ""
    for i in content:
        out += i + ' '
    return out


# Receives the output from NMAP and generates both json and txt ouput from it
def readFromNmapOutput(nmapOutput):

    data = {'devices': []}
    out = ""; ip = ""; port = []; portState = []; service = []; i = 0
    for line in nmapOutput:
        if "Nmap scan report" in line:
            ip = line.split(' ')[4].rstrip()
            out += "Device: " + ip + "\n"
        elif "tcp" in line or "udp" in line:
            line = list(filter(lambda a: len(a) > 0, line.split(' ')))
            port.append(line[0])
            portState.append(line[1])
            service.append(line[2].rstrip())
            out += "\t" + port[i] + "  " + portState[i] + "  " + service[i] + "\n"
            i += 1
        elif line == "\n":
            services = []
            for j in range(0, len(port)):
                services.append({
                    'Port': port[j],
                    'State': portState[j],
                    'Name': service[j]
                })
            data['devices'].append({
                'IP': ip,
                'Services': services
            })
            ip = ""; port = []; portState = []; service = []; i = 0
            out += "\n"
    out += "\n"
    return [data, out]


# Spots the difference between previous and current txt files and generates the
# logging file containing the respective differences to warn the admin/user
def generateLog(oldData, newData):

    retFlag = False # flag that indicates if theres is a new IoT device
    out = "*************** LOGGING PORT SCAN REPORT ***************\n\n"
    # Constructs 2 arrays of Devices based on old and new data
    oldDev = []; ip = ''; serv = []; first = True
    old = oldData.splitlines(); new = newData.splitlines()
    for line in old:
        if "Device" in line:
            if first == False:
                oldDev.append(Device(ip, serv))
                serv = []
            ip = line.split(' ')[1]
            first = False
        elif "tcp" in line or "udp" in line:
            serv.append(line.strip())
    oldDev.append(Device(ip, serv))
    newDev = []; ip = ''; serv = []; first = True
    for line in new:
        if "Device" in line:
            if first == False:
                newDev.append(Device(ip, serv))
                serv = []
            ip = line.split(' ')[1]
            first = False
        elif "tcp" in line or "udp" in line:
            serv.append(line.strip())
    newDev.append(Device(ip, serv))
    # Obtains the differences in devices
    ipNew = set(); ipOld = set()
    for obj in newDev:
        ipNew.add(obj.ip)
    for obj in oldDev:
        ipOld.add(obj.ip)
    dif1 = list(ipNew - ipOld)
    dif2 = list(ipOld - ipNew)
    if dif1:
        out += "Detected new devices in the network:\n"
        for d in dif1:
            out += d + "\n"
        out += "\n"
        retFlag = True
    if dif2:
        out += "Detected devices removed from the network (or currently down):\n"
        for d in dif2:
            out += d + "\n"
        out += "\n"   
    # Obtains the  differences in common devices' ports
    for obj1 in newDev:
        for obj2 in oldDev:
            if obj1.ip == obj2.ip:
                dif1 = list(set(obj1.services) - set(obj2.services))
                if dif1:
                    out += "It was detected that the following ports of device " + obj1.ip + \
                        " are now opened/filtered:\n"
                    for d in dif1:
                        out += d + "\n"
                    out += "\n" 
    for obj1 in oldDev:
        for obj2 in newDev:
            if obj1.ip == obj2.ip:
                dif2 = list(set(obj1.services) - set(obj2.services))
                if dif2:
                    out += "It was detected that the following ports of device " + obj1.ip + \
                        " are now closed:\n"
                    for d in dif2:
                        out += d + "\n"
                    out += "\n" 
    return [retFlag, out]
            

# Scans IoT devices with nmap and compares the result with the last scan
# if changes occur, generates a new log file and alerts the admin/user
def nmapScanning(jsonFile, txtFile):

    retFlag = False
    ipAddresses = getIPsFromFile()
    command = "nmap -sT -Pn -n " + ipAddresses # Adicionar --max-parallelism 100 ???
    #command = ['nmap', '-sT', '-Pn', '-n', ipAddresses]
    try:
        scan = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        #scan = subprocess.Popen(command, universal_newlines=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        scan.wait()
        ret = readFromNmapOutput(scan.stdout)
    finally:
        scan.kill()
    data = ret[0]; newTxt = ret[1]
    if jsonFile == None and txtFile == None:
        date = datetime.now().strftime("%Y-%m-%d_%I:%M:%S%p")
        with open('./scans/json/' + date + ".json", 'w') as newJsonFile, \
            open('./scans/text/' + date + ".txt", 'w') as newTxtFile:
            json.dump(data, newJsonFile, indent=4, sort_keys=False)
            newTxtFile.write(newTxt)
    else:
        oldData = jsonFile.read()
        obj = json.loads(oldData)
        if obj['devices'] != data['devices']:

            #new
            ipAddresses = getIPsFromFile()
            command = "nmap -sT -Pn -n " + ipAddresses # Adicionar --max-parallelism 100
            #command = ['nmap', '-sT', '-Pn', '-n', ipAddresses]
            try:
                scan = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE)
                #scan = subprocess.Popen(command, universal_newlines=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
                scan.wait()
                ret = readFromNmapOutput(scan.stdout)
            finally:
                scan.kill()
            data = ret[0]; newTxt = ret[1]
            if obj['devices'] != data['devices']:
            #new

                print("ALERT: Theres is a change in your devices' ports state!\nCheck the log file ASAP!")
                date = datetime.now().strftime("%Y-%m-%d_%I:%M:%S%p")
                with open('./scans/json/' + date + ".json", 'w') as jsonFile, \
                    open('./scans/text/' + date + ".txt", 'w') as newTxtFile,  \
                    open('./scans/logs/' + date + ".log", 'w') as logFile:
                    json.dump(data, jsonFile, indent=4, sort_keys=False)
                    newTxtFile.write(newTxt)
                    oldTxt = txtFile.read()
                    log = generateLog(oldTxt, newTxt)
                    retFlag = log[0]
                    logFile.write(log[1])
                # TODO: send email and/or sms
                subj = "[Home Security] Alert: Your devices' ports state have changed"
                msg = "Dear user,\n\nThis email is reporting an anomaly that was detected in your network.\nIt seems that there was a change detected in your devices' ports state.\nWe strongly recommend you to read carefully the attached logging file.\n\nBest regards,\nHomeSecurity Team"
                filename = "./scans/logs/" + date + ".log"
                sendEmail(subj, msg, filename)
                sms = "\nWe have detected an anomaly in your network! It seems that there was a change detected in your devices' ports state. We strongly recommend you to read carefully the logging file sent by email.\nBest regards,\nHomeSecurity Team"
                sendSMS(sms)
    return retFlag
    

def portScanner():

    try:
        newestFile1 = newestFileFromDir('./scans/json/') # Gets most recent file in scans/json/
        newestFile2 = newestFileFromDir('./scans/text/') # Gets most recent file in scans/text/
        if newestFile1 == None and newestFile2 == None: # Empty directories => first run
            ret = nmapScanning(None, None)
        else:
            jsonFile = open(newestFile1, 'r') # Opens json file
            txtFile = open(newestFile2, 'r') # Opens txt file
            ret = nmapScanning(jsonFile, txtFile)
    finally:
        if newestFile1 != None and newestFile2 != None:
            jsonFile.close()
            txtFile.close
    return ret

        
if __name__ == "__main__":

    portScanner()
