# HomeSecurity: Network-based Intrusion Detection System for domestic IoT
Application developed in Python specifically for Raspberry Pi running Kali Linux.  
HomeSecurity was desgined for domestic networks and it's main purpose is to detected intrusions (or attempts of intrusion) in IoT devices and warn the user via email and SMS. Plus, it also implements the following features:   
- Traffic counting (weekly reporting the statistics to the user)
- Port analysis and detection of unexpected changes
- Vulnerabilities inspection and verification


## Install
There is a small script called `install.sh` that creates the necessary directories and installs (with pip3) every package needed by the application. It receives two arguments:   

- Your email address
- Your phone number

```
./install.sh iotnids@homesecurity.com +351912345678
```

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


## Issues
Since the email and SMS services run on a remote server, this feature will not work unless the server is running. To avoid unnecessary costs, the remote server is currently shutdown.   
Instead, we recommend you not to use this feature and comment out the two functions in `alertUser.py`. If you really want to try this feature, you can easily implement it locally.