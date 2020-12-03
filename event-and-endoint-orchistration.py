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
    CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    LAST_RUN_TIME_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_run_time.txt")
    ENDPOINTS_CURRENTLY_SCANNING_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints_currently_scanning")

    # Getting configuration info
    CONFIG_INFO = get_json_data(CONFIG_FILE_PATH)

    # Setting malicious event types
    LIST_OF_MALICIOUS_EVENT_TYPES = CONFIG_INFO.event_types_to_trigger_isolation_and_scan

    # Setting API credentials
    AMP_ID = CONFIG_INFO.credentials.amp.id
    AMP_KEY = CONFIG_INFO.credentials.amp.key
    
    while True:
        # Setting time values
        last_run_time = get_last_run_time(LAST_RUN_TIME_FILE_PATH)
        current_run_time = get_current_time()
        
        # The main act of the show
        amp_events = get_amp_events(AMP_ID, AMP_KEY)

        for event in amp_events.data:
            if int(event['timestamp']) > int(last_run_time): # Only run against events that havent already been checked (current time delta)
                if event['event_type'] in LIST_OF_MALICIOUS_EVENT_TYPES:
                    with open(ENDPOINTS_CURRENTLY_SCANNING_FILE_PATH, 'r') as f: # Keeps mutiple events in the current time delta from triggering multiple scans
                        endpoints_currently_scanning = f.readlines()
                    if event['connector_guid'] + "\n" not in endpoints_currently_scanning: # Avoids running a 2nd scan if another is already running 
                        start_full_scan(event['connector_guid'], AMP_ID, AMP_KEY)
                        start_isolation(event['connector_guid'], AMP_ID, AMP_KEY)
                        email_alert(CONFIG_INFO, ("Starting Full Scan - " + event['event_type']), event['computer'])
                        append_to_end_of_file(ENDPOINTS_CURRENTLY_SCANNING_FILE_PATH, event['connector_guid'])
                elif event['event_type'] == "Scan Completed, No Detections":
                    stop_isolation(['connector_guid'],AMP_ID, AMP_KEY)
                    remove_from_file(ENDPOINTS_CURRENTLY_SCANNING_FILE_PATH, event['connector_guid'])
                elif event['event_type'] == "Scan Completed With Detections":
                    email_alert(CONFIG_INFO, "Scan Completed With Detections", event['computer'])
                    remove_from_file(ENDPOINTS_CURRENTLY_SCANNING_FILE_PATH, event['connector_guid'])
        
        # Updates the last run time for the next loop to reference
        update_last_run_time(LAST_RUN_TIME_FILE_PATH, current_run_time)

        # Wait until next cycle
        time.sleep(60) # 1 minute wait before looping
     

def get_last_run_time(last_run_time_file):
    if not (os.path.isfile(last_run_time_file)):
        f = open(last_run_time_file, "w")
        f.write("847584000")
        f.close()
    return open(last_run_time_file, "r").read()


def get_current_time():
    return str(int(time.time())) #  returns a unix timestamp that looks like: 1606920204 


def update_last_run_time(last_run_time_file, updated_time):
    f = open(last_run_time_file, "w")
    f.write(updated_time)
    f.close()


def get_json_data(file):
    with open(file) as json_file:
        data = json.load(json_file,object_hook=json_decoder) # works with the json_decoder function
    return data


def json_decoder(dictionary):
    return namedtuple('X', dictionary.keys())(*dictionary.values())


def get_amp_events(AMP_ID, AMP_KEY):
    return json_decoder((requests.get('https://api.amp.cisco.com/v1/events', auth=HTTPBasicAuth(AMP_ID, AMP_KEY))).json())


def start_isolation(guid, AMP_ID, AMP_KEY):
    pass
    #url = "https://api.amp.cisco.com/v1/computers/{}/isolation".format(guid)
    #requests.put(url, auth=HTTPBasicAuth(AMP_ID, AMP_KEY))


def stop_isolation(guid, AMP_ID, AMP_KEY):
    pass
    #url = "https://api.amp.cisco.com/v1/computers/{}/isolation".format(guid)
    #requests.delete(url, auth=HTTPBasicAuth(AMP_ID, AMP_KEY))


def start_full_scan(guid, AMP_ID, AMP_KEY):
    pass # https://i.imgur.com/kBrDBwb.jpg


def append_to_end_of_file(file, string):
    with open(file,'a') as f:
        f.write(string + "\n")
        f.close()


def remove_from_file(file, string):
    with open(file, 'r+') as f:
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            if line != string + "\n":
                f.write(line)
        f.truncate()
    

def email_alert(CONFIG_INFO, alert, computer_info):
    email_body = "<h1>Alert for " + computer_info['hostname'] + "</h1><h2>" + alert + "</h2><br><br><b>Computer Info:</b><br><i>" + \
                    re.sub(r'[[\]{}]', '', (str(computer_info)).replace(',', '<br>')) + "</i>" # re cleans up all leftover [] and {} in the JSON
    msg = EmailMessage()
    msg['From'] = CONFIG_INFO.email.from_email
    msg['To'] = CONFIG_INFO.email.to_email
    msg['Subject'] = f'Alert from amp-autoscan-and-isolation'
    msg.set_content(email_body, 'html')
    s = smtplib.SMTP(CONFIG_INFO.email.email_server)
    s.send_message(msg)
    s.quit()


if __name__ == "__main__":
    main()
