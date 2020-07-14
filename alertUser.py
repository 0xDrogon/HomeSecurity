#!/usr/bin/python3
import os
import smtplib
import xmlrpc.client


def sendEmail(subj, msg, filename):

    dst = os.environ.get('EMAIL_DST')
    conn = xmlrpc.client.ServerProxy('http://localhost:9090')
    with open(filename, 'rb') as f:
        binaryData = xmlrpc.client.Binary(f.read())
    conn.sendEmail(dst, subj, msg, filename, binaryData)


def sendSMS(message):

    dst = os.environ.get('NUMBER_DST')
    conn = xmlrpc.client.ServerProxy('http://localhost:9090')
    conn.sendSMS(dst, message)
