import json
import reqeusts
import os
import sys

vtapi = open("vt_api_key").read().strip() 

def get_file_report(hvalue, apikey):
    url = 'https://www.virustotal.com/api/v3/files/' + hvalue
    headers = {'Accept':'application/json', 'x-apikey': apikey}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return False

    return response.json()

def file_rescan(hvalue, apikey):
    url = 'https://www.virustotal.com/api/v3/files/{}/analyse'.format(hvalue)
    headers = {'Accept':'application/json', 'x-apikey': apikey}
    response = requests.post(url, headers=headers)

    if response.status_code != 200:
        return False

    return True

def file_upload(fpath, apikey):
    url = "https://www.virustotal.com/api/v3/files" 
    headers = {
        'Accept':'application/json', 
        "x-apikey": apikey
    }

    files = {"file": ("file.exe", open(fpath, "rb"), "application/x-msdownload")}
    response = requests.post(url,  headers=headers, files=files)

    if response.status_code != 200:
        return False

    return response.json()["sha256"]

