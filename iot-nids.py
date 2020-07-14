#!/usr/bin/python3
from networkScan import networkScanner, get_ip_network
from iotIdent import iotIdentifier
from portScan import portScanner
from vulnScan import vulnerabilityScanner, vuln_flag
from arpSpoof import arpSpoofer, arp_flag
from snortController import snortController, snort_flag
from counter import counterTraffic, counter_flag, write_data_to_file, resetData
from alertUser import sendEmail, sendSMS
from datetime import datetime

import time
import json
import threading
import subprocess, signal
import os
import sys


# Global Variable
kill_flag = False

def threadForVulnScan(keepRunning):
    global kill_flag
    if keepRunning:
        while True:
            print("Scanning for vulnerabilities infinitely...")
            vulnerabilityScanner()
            print("Vulnerabilities scanning completed!")
            for i in range(8640): # sleep during half a day
                if kill_flag:
                    break
                time.sleep(5)
            if kill_flag:
                break
    else:
        print("Scanning for vulnerabilities only once...")
        vulnerabilityScanner()
        print("Vulnerabilities scanning completed!")


def snortSendEmail():
    global kill_flag
    tmpDir = "snortDir/tmp/"
    persistentDir = "snortDir/"
    while not kill_flag:
        date = datetime.now().strftime("%Y-%m-%d_%I:%M:%S%p")
        tmpDirs = os.listdir(tmpDir)
        for directory in tmpDirs:
            files = os.listdir(tmpDir + directory)
            for file in files:
                #print(file)
                #move file
                persistentDirs = os.listdir(persistentDir)
                if not directory in persistentDirs:
                    os.mkdir(persistentDir + directory)
                filename = persistentDir + directory + '/' + file + '_' + date + ".log"
                os.replace(tmpDir + directory + '/' + file, filename)
                #send email
                print("Sending snort email...")
                subj = "[Home Security] Alert: Possible attack or intrusion in your network"
                msg = "Dear user,\n\nThis email is reporting an anomaly that was detected in your network.\nIt seems like someone is attacking your IoT devices or exploiting them to have access to your network.\nWe strongly recommend you to read carefully the attached logging file.\n\nBest regards,\nHomeSecurity Team"
                sendEmail(subj, msg, filename)
                print("Email sent!")
                print("Sending snort SMS...")
                sms = "\nWe have detected an anomaly in your network! It seems like someone is attacking your IoT devices or exploiting them to have access to your network. We strongly recommend you to read carefully the logging file sent by email.\nBest regards,\nHomeSecurity Team"
                sendSMS(sms)
                print("SMS sent!")
        time.sleep(60)


def counterSendEmail():
    global kill_flag
    tmpFile = "counters/tmp/counter.json"
    counterDir = "counters/"
    while not kill_flag:
        time.sleep(60*5)
        date = datetime.now().strftime("%Y-%m-%d_%I:%M:%S%p")
        #move file
        filename = counterDir + date + ".json"
        os.replace(tmpFile, filename)
        resetData()
        #send email
        print("Sending counter email...")
        subj = "[Home Security] Report: Weekly update of your IoT devices' traffic statistics"
        msg = "Dear user,\n\nThe weekly report of your IoT devices' traffic is in the attached file.\n\nBest regards,\nHomeSecurity Team"
        sendEmail(subj, msg, filename)
        print("Email sent!")
        print("Sending snort SMS...")
        sms = "\nWe have sent you the weekly report of your IoT devices' traffic by email.\nBest regards,\nHomeSecurity Team"
        sendSMS(sms)
        print("SMS sent!")
       

"""
def mainthread():# Não sei o nome desta Thread
    oldData = networkScanner()
    iotIdentifier()
    time.sleep(15)
    while True:
        print("Scanning the network for devices...")
        newData = networkScanner()
        #print(newData)
        if oldData['devices'] != newData['devices']:
            print("Change detected!")
            time.sleep(10)
            newData = networkScanner()
            print(newData)
            print("Identifying IoT devices...")
            iotIdentifier()
        time.sleep(10)
        print("Scanning ports...")
        if portScanner():
            print("Launching thread...")
            tempThread = threading.Thread(target=threadForVulnScan, args=[False])
            tempThread.start()
            print("Thread successfully launched!")
        print("Finished! Starting again...\n")
        oldData = newData
        time.sleep(20)
"""

def main():
    global kill_flag
    print("Starting program...")
    oldData = networkScanner(1)
    iotIdentifier()
    print("Launching threads...")
    vulnScanThread = threading.Thread(target=threadForVulnScan, args=[True], daemon=True)
    vulnScanThread.start()
    arpThread = threading.Thread(target=arpSpoofer, args=[], daemon=True)
    arpThread.start()
    time.sleep(10)
    net = get_ip_network()
    snortThread = threading.Thread(target=snortController, args=(net ,"eth0"), daemon=True)
    snortThread.start()
    time.sleep(10)
    counterThread = threading.Thread(target=counterTraffic, args=["eth0"],daemon=True)
    counterThread.start()
    snortEmailThread = threading.Thread(target=snortSendEmail, args=[],daemon=True)
    snortEmailThread.start()
    counterEmailThread = threading.Thread(target=counterSendEmail, args=[],daemon=True)
    counterEmailThread.start()
    print("Threads successfully launched!")

    try:
        while True:
            print("Scanning the network for devices...")
            newData = networkScanner(3)
            #print(newData)
            if oldData['devices'] != newData['devices']:
                print("Change detected! (1)")
                time.sleep(10)
                newData = networkScanner(3)
                #print(newData)
                if oldData['devices'] != newData['devices']:
                    print("Change detected! (2)")
                    print("Identifying IoT devices...")
                    iotIdentifier()
            time.sleep(10)
            print("Scanning ports...")
            if portScanner():
                print("Launching thread...")
                tempThread = threading.Thread(target=threadForVulnScan, args=[False])
                tempThread.start()
                print("Thread successfully launched!")
            print("Finished! Starting again...\n")
            oldData = newData
            time.sleep(10) 
            write_data_to_file()
    except:
        pass
    print("\nExiting the program...")
    kill_flag = True
    vuln_flag()
    print("Ending vuln thread...")
    vulnScanThread.join()
    print("Vuln thread terminated...")
    snort_flag()
    print("Ending snort thread...")
    snortThread.join()
    print("Snort thread terminated...")
    arp_flag()
    print("Ending ettercap thread...")
    arpThread.join()
    print("Ettercap thread terminated...")
    counter_flag()
    print("Ending counter thread...")
    counterThread.join()
    print("Killing remaining processes...")
    p = subprocess.Popen(['ps', '-A'], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    for line in p.stdout:
        if 'ettercap' in line or 'snort' in line or 'nmap' in line or 'searchsploit' in line:
            pid = int(line.split(None, 1)[0])
            print("Killing ", pid, "...")
            os.kill(pid, signal.SIGKILL)
            print(pid, " killed!")
    time.sleep(3)
    print("Program successfully terminated!\n")


if __name__ == "__main__":
    main()
    #sys.exit(0)
