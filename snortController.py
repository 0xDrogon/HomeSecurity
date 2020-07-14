#!/usr/bin/python3
import os
import subprocess
import time
import signal
import threading

# Global Variable
flag = 0


def run_command(network, interface):
    cmd = "exec snort -d -h " + network + " -i " + interface + " -A console -c /etc/snort/snort.conf -l snortDir/tmp/ -K ascii"
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)


def snortController(network, interface):
    global flag    
    pro = run_command(network,interface)
    
    while flag == 0:
        pass
        
    pro.kill()

        
def snort_flag():
    global flag
    flag = 1


if __name__ == "__main__":
    
    x = threading.Thread(target=snortController, args=("192.168.88.0/24", "eth0"))
    x.start()
    time.sleep(10)
    snort_flag()
