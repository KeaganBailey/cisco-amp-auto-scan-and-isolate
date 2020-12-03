import os
import time
import requests
from requests.auth import HTTPBasicAuth
import json
from collections import namedtuple
import smtplib
from email.message import EmailMessage
import re

def main():
    # Getting locally stored data
    config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    last_run_time_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_run_time.txt")
    endpoints_currently_scanning_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints_currently_scanning")

    # Getting configuration info
    config_info = get_Json_Data(config_file)

    # Setting email info
    support_email = config_info.emails.support_email

    # Setting malicious event types
    list_of_malicious_event_types = config_info.event_types_to_trigger_isolation_and_scan

    # Setting API credentials
    amp_id = config_info.credentials.amp.id
    amp_key = config_info.credentials.amp.key
    
    while True:
        # Setting time values
        last_run_time = get_Last_Run_Time(last_run_time_file_path)
        current_run_time = get_Current_Time()
        
        # The main act of the show
        amp_events = get_Amp_Events(amp_id, amp_key)

        for event in amp_events.data:
            if int(event['timestamp']) > int(last_run_time): # Only run against events that havent already been checked
                if event['event_type'] in list_of_malicious_event_types:
                    with open(endpoints_currently_scanning_file, 'r') as f: # Runs every loop so that multiple events that would trigger scan/isolation in quick succession (within the same last run / current run delta) dont trigger multiple scan/isolation events and emails
                        endpoints_currently_scanning = f.readlines()
                    if event['connector_guid'] + "\n" not in endpoints_currently_scanning: # avoids running these commands twice if a previous event already triggered isolation/scan, but scan did not complete yet.
                        startFullScan(event['connector_guid'], amp_id, amp_key)
                        startIsolation(event['connector_guid'], amp_id, amp_key)
                        emailAlert(support_email, ("Starting Full Scan - " + event['event_type']), event['computer'])
                        appendToEndOfFile(endpoints_currently_scanning_file, event['connector_guid'])
                elif event['event_type'] == "Scan Completed, No Detections":
                    stopIsolation(['connector_guid'],amp_id, amp_key)
                    removeFromFile(endpoints_currently_scanning_file, event['connector_guid'])
                elif event['event_type'] == "Scan Completed With Detections":
                    emailAlert(support_email, "Scan Completed With Detections", event['computer'])
                    removeFromFile(endpoints_currently_scanning_file, event['connector_guid'])
        
        # Updates the last run time for the next loop to reference
        update_Last_Run_Time(last_run_time_file_path, current_run_time)

        # Wait until next cycle
        time.sleep(60) # 1 minute wait before looping
     

def get_Last_Run_Time(last_run_time_file):
    if not (os.path.isfile(last_run_time_file)):
        f = open(last_run_time_file, "w")
        f.write("847584000")
        f.close()

    return open(last_run_time_file, "r").read()


def get_Current_Time():
    return str(int(time.time())) #  returns a unix timestamp that looks like: 1606920204 


def update_Last_Run_Time(last_run_time_file, updated_time):
    f = open(last_run_time_file, "w")
    f.write(updated_time)
    f.close()


def get_Json_Data(file):
    with open(file) as json_file:
        data = json.load(json_file,object_hook=json_Decoder) # works with the json_Decoder function
    return data


def json_Decoder(dictionary):
    return namedtuple('X', dictionary.keys())(*dictionary.values())


def get_Amp_Events(amp_id, amp_key):
    return json_Decoder((requests.get('https://api.amp.cisco.com/v1/events', auth=HTTPBasicAuth(amp_id, amp_key))).json())


def startIsolation(guid, amp_id, amp_key):
    pass
    #url = "https://api.amp.cisco.com/v1/computers/{}/isolation".format(guid)
    #requests.put(url, auth=HTTPBasicAuth(amp_id, amp_key))


def stopIsolation(guid, amp_id, amp_key):
    pass
    #url = "https://api.amp.cisco.com/v1/computers/{}/isolation".format(guid)
    #requests.delete(url, auth=HTTPBasicAuth(amp_id, amp_key))

def startFullScan(guid, amp_id, amp_key):
    pass # https://i.imgur.com/kBrDBwb.jpg


def appendToEndOfFile(file, string):
    with open(file,'a') as f:
        f.write(string + "\n")
        f.close()


def removeFromFile(file, string):
    with open(file, 'r+') as f:
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            if line != string + "\n":
                f.write(line)
        f.truncate()
    

def emailAlert(email, alert, computer_info):
    email_body = "<h1>Alert for " + computer_info['hostname'] + "</h1><h2>" + alert + "</h2><br><br><b>Computer Info:</b><br><i>" + re.sub('[[\]{}]', '', (str(computer_info)).replace(',', '<br>')) + "</i>"
    msg = EmailMessage()
    msg['From'] = "no-reply@cohencpa.com"
    msg['To'] = email
    msg['Subject'] = f'Alert from amp-autoscan-and-isolation'
    msg.set_content(email_body, 'html')
    s = smtplib.SMTP('mail.cohencpa.com')
    s.send_message(msg)
    s.quit()


if __name__ == "__main__":
    main()
