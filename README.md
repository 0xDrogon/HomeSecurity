# HomeSecurity: Network-based Intrusion Detection System for domestic IoT
Application developed in Python specifically for Raspberry Pi running Kali Linux.  
HomeSecurity was desgined for domestic networks and it's main purpose is to detected intrusions (or attempts of intrusion) in IoT devices. Plus, it also implements the following features:   
- Traffic counting (weekly reporting the statistics to the user)
- Port analysis and detection of unexpected changes
- Vulnerabilities inspection and verification


## Install
There is a small script called `install.sh` that creates the necessary directories and installs (with pip3) every package needed by the application.  
Moreover, you need to have the following programs installed in your Raspberry Pi in order for everything to work (since HomeSecurity uses them):  
- Nmap
- Ettercap
- Snort
- Searchsploit


## Run
The `iot-nids.py` corresponds to the main file of the application and that is the one you need to execute with Python in order to run HomeSecurity.  
We recommend you to use Python 3.7, since that was the version used for developing and testing the application.  
```
python3.7 iot-nids.py
```