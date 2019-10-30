import json
import socket
import subprocess
import uuid
import time
import Evtx.Evtx as evtx
import xmltodict
import yaml
import os.path
import pickle
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl.search import Search
def save(obj):
    with open("saved_index", 'wb') as fobj:
        pickle.dump(obj, fobj)

def load(file_name):
    with open(file_name, 'rb') as fobj:
        return pickle.load(fobj)

with open("config.yaml", "r") as yamlfile:
    config = yaml.safe_load(yamlfile)

conf = {
    'default': {
        'hosts': [
            {
                'host': config['elastic']['host'],
                'port': config['elastic']['port']
            }
        ]
    }
}

connections.configure(**conf)

# connection with Elasticsearch DB
es = Elasticsearch([{'host': config['elastic']['host'], 'port': config['elastic']['port']}])


# function to get WLAN ip
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


# function to get system mac
def get_mac():
    mac_addr = hex(uuid.getnode()).replace('0x', '')
    mac_addr = ':'.join(mac_addr[i: i + 2] for i in range(0, 11, 2))
    return mac_addr


# function to get unique processor id
def get_uuid():
    current_machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    return current_machine_id


# function to convert xml into dictionary
def convert_xml_to_json(data_in_xml):
    abx = json.loads(json.dumps(xmltodict.parse(data_in_xml, attr_prefix='', cdata_key='text')))
    # for data in abx['Event']['EventData']['Data']:
    #     if len(data) == 2 and "Name" in data and data['Name'] == "RuleName":
    #         d = data['text'].split(',')
    #         rule = {}
    #         rule['technique_id'] = d[0].split('=')[1]
    #         rule['technique_name'] = d[1].split('=')[1]
    #         abx['Event']['EventData']['Data'].append(rule)
    #         abx['Event']['EventData']['Data'].remove(data)
    return abx


# Function for extracting data from sysmon evtx file and store on server
def bulk_insertion():
    ind = 1
    oldL = 0
    # mac = str(get_mac())
    # ip = str(get_ip_address())
    # uuidd = str(get_uuid())

    with evtx.Evtx(config['file']['path']) as rec:
        # re = list(rec.records())
        actions = []
        while True:
            new = list(rec.records())
            newl = len(new)
            if new and newl > oldL:
                while (newl > oldL):
                    data = convert_xml_to_json(new[oldL].xml())
                    oldL = oldL + 1
                    action = {'_index': config['elastic']['index'], '_type': config['elastic']['title'], '_id': ind,
                              '_source': data}
                    actions.append(action)
                    if ind % 50 == 0:
                        print("Inserting the records")
                        helpers.bulk(es, actions)
                        actions = []
                    ind += 1
            else:
                time.sleep(0.5)

def conver_dict(data,abx):

    if len(data) == 2 and "Name" in data and data['Name'] == "RuleName":
        d = data['text'].split(',')
        rule = {}
        rule['technique_id'] = d[0].split('=')[1]
        rule['technique_name'] = d[1].split('=')[1]
        abx['Event']['EventData']['Data'].append(rule)
        abx['Event']['EventData']['Data'].remove(data)
        return abx
    elif len(data) == 1 and "Name" in data and data['Name'] == "RuleName":
        rule = {}
        rule['technique_id'] = ''
        rule['technique_name'] = ''
        abx['Event']['EventData']['Data'].append(rule)
        abx['Event']['EventData']['Data'].remove(data)
        return abx
    else:
        return None




def bulk_test_insertion():
    if os.path.exists('saved_index'):
        oldL = load('saved_index')
        ind = load('saved_index')
    else:
        oldL = 0
        ind = 0
    actions = []
    with evtx.Evtx(config['file']['path']) as rec:
        while True:
            new = list(rec.records())
            newl = len(new)
            if newl > oldL and newl - oldL >= 50:
                while newl > oldL:
                    abx = convert_xml_to_json(new[oldL].xml())
                    for data in abx['Event']['EventData']['Data']:
                        go_get = conver_dict(data, abx)
                        if go_get != None:
                            sav_dict = go_get
                        if len(data) == 2 and "Name" in data and data['Name'] == "Image":
                            if 'C:\Windows\System32\wbem\WMIC.exe' == data['text'] \
                                    or 'C:\Windows\System32\SppExtComObj.Exe' == data['text'] \
                                    or "C:\\Users\\admin\AppData\Local\Programs\Python\Python37\pythonw.exe" == data[
                                'text']:
                                print("Noise")
                            else:
                                action = {'_index': config['elastic']['index'], '_type': config['elastic']['title'], '_id': ind,
                                          '_source': sav_dict}
                                actions.append(action)
                                ind += 1

                    oldL += 1
                    save(oldL)
                    if ind % 50 == 0:
                        print("Inserting the records")
                        helpers.bulk(es, actions)
                        actions = []

            else:
                time.sleep(0.5)
    outfile.close()


bulk_test_insertion()
