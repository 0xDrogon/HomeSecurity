#!/usr/bin/python3
import subprocess
import os
import threading
import signal
from alertUser import sendEmail, sendSMS


# Global Variable
flag = 0
stop_threads = False


# Retrieves IP addresses from the hosts file
def getIPsFromFile(file):
    
    content = file.readlines()
    content = [x.split(' ')[0] for x in content]
    #content.pop() # tirar ou deixar ???
    return content


def check_flag(pro):

    global flag
    while flag == 0:
        if not stop_threads:
            pass
        else:
            break
    pro.kill()


def vuln_flag():
    
    global flag
    flag = 1


def nmapPortScan(host):
    global stop_threads
    command = "nmap -sT -Pn -n -sV -oX vulns/xml/" + host + ".xml " + host # Adicionar --max-parallelism 100 ???
    #command = ['nmap', '-sT', '-Pn', '-n', '-sV', "-oX vulns/xml/", host + ".xml", host]
    try:
        scan = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        #scan = subprocess.Popen(command, universal_newlines=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE,stderr=subprocess.PIPE)
        t = threading.Thread(target = check_flag, args=[scan])
        t.start()
        scan.wait()
    finally:
        scan.kill()
        stop_threads = True
        t.join()
        stop_threads = False


def searchForVulns(host):
    global stop_threads
    log = "*************** LOGGING VULNERABILITY SCAN REPORT ***************\n\n" \
        + "The table below presents the possible vulnerabilities found on this device:\n\n"
    with open("vulns/logs/" + host + ".log", 'w') as logfile:
        logfile.write(log)
    oldSize = os.path.getsize("vulns/logs/" + host + ".log")
    command = "searchsploit -w --colour --nmap vulns/xml/" + host + ".xml >> vulns/logs/" + host + ".log"
    try:
        search = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t = threading.Thread(target=check_flag, args=[search])
        t.start()
        search.wait()
    finally:
        search.kill()
        stop_threads = True
        t.join()
        stop_threads = False
    newSize = os.path.getsize("vulns/logs/" + host + ".log")
    if oldSize == newSize:
        with open("vulns/logs/" + host + ".log", 'w') as logfile:
            log = "*************** LOGGING VULNERABILITY SCAN REPORT ***************\n\n" \
                + "No vulnerabilities were found on this device!\n"
            logfile.write(log)
    else:
        #TODO: verify difference in files (NO CAN DO!)
        #send email and/or sms
        subj = "[Home Security] Alert: Possible vulnerability detected in your device"
        msg = "Dear user,\n\nThis email is reporting an anomaly that was detected in your network.\nIt seems that it was detected a possible vulnerability in one of your devices.\nWe strongly recommend you to read carefully the attached logging file.\n\nBest regards,\nHomeSecurity Team"
        filename = "vulns/logs/" + host + ".log"
        sendEmail(subj, msg, filename)
        sms = "\nWe have detected an anomaly in your network! It seems that it was detected a possible vulnerability in one of your devices. We strongly recommend you to read carefully the logging file sent by email.\nBest regards,\nHomeSecurity Team"
        sendSMS(sms)


def vulnerabilityScanner():

    with open("hosts/hosts.txt", 'r') as hostsFile:
        ipAddresses = getIPsFromFile(hostsFile)
    for ip in ipAddresses:
        if flag == 1:
            break
        nmapPortScan(ip)
        searchForVulns(ip)
        

if __name__ == "__main__":

    vulnerabilityScanner()
