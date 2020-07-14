#!/bin/bash
mkdir hosts
mkdir scans
mkdir scans/json scans/text scans/logs 
mkdir vulns
mkdir vulns/xml vulns/logs
mkdir counters
mkdir counters/tmp
mkdir snortDir
mkdir snortDir/tmp
export EMAIL_SRC=iotnids.isel@gmail.com
export EMAIL_DST=tiagofsdomingues@gmail.com
token=$(<.email/token.txt)
export EMAIL_SRC_TKN=$token
echo "Installation completed!"
