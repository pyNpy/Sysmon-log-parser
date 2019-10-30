import yaml
import json
import xmltodict
import Evtx.Evtx as evtx

with open("config.yaml", "r") as yamlfile:
    config = yaml.safe_load(yamlfile)


def convert_xml_to_json(data_in_xml):
    convertion = json.loads(json.dumps(xmltodict.parse(data_in_xml, attr_prefix='', cdata_key='text')))
    return convertion


def corelation():
    with evtx.Evtx(config['file']['path']) as rec:
        new = list(rec.records())
        # print(len(new))
        ind = 0
        while (len(new) > ind):
            abx = convert_xml_to_json(new[ind].xml())
            ind += 1
            yield abx


def get_process_id(items):
    for data in items['Event']['EventData']['Data']:
        if len(data) == 2 and "Name" in data and data['Name'] == "ProcessId":
            return data['text']


def get_parent_process_id(items):
    for data in items['Event']['EventData']['Data']:
        if len(data) == 2 and "Name" in data and data['Name'] == "ParentProcessId":
            return data['text']


def data_inparent(arrng,proid):
    for data in arrng:
        pid = get_parent_process_id(data)
        if proid == pid and pid != None:
            print(data)


def same_p_id(proid,arrng,rcdid):
    for data in arrng:
        pid = get_process_id(data)
        rcdid1 = data['Event']['System']['EventRecordID']
        if proid == pid and pid != None and rcdid != rcdid1:
            print(data)

arrng = []
def get_search():
    index = 0
    arrng = corelation()
    for items in arrng:
        proid = get_process_id(items)
        rcdid = items['Event']['System']['EventRecordID']
        if proid != None:
            same_p_id(proid, arrng, rcdid)
    print("Done")
    for data in arrng:
        print("1")
        proid = get_process_id(data)
        print("2")
        if proid != None:
            print("3")
            data_inparent(arrng, proid)
            print("4")

get_search()
