#!/bin/bash
email=$1
number=$2
mkdir hosts
mkdir scans
mkdir scans/json scans/text scans/logs 
mkdir vulns
mkdir vulns/xml vulns/logs
mkdir counters
mkdir counters/tmp
mkdir snortDir
mkdir snortDir/tmp
pip3 install twilio
pip3 install scapy
echo EMAIL_DST=$email >> /etc/environment
echo NUMBER_DST=$number >> /etc/environment
echo "Installation completed!"
