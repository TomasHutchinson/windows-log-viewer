import os
from evtx import PyEvtxParser
import json
from functools import cmp_to_key
import csv

import subprocess

import argparse
# import xml.etree.ElementTree as ET

arg = argparse.ArgumentParser(description="A script that  helps simplify log files.")
arg.add_argument("--log-dir", help="The directory of your evtx log files / location of a single evtx log file", default="./")
arg.add_argument('--filters', help='Filters for certain properties', default=['EventID'], action='append')
arg.add_argument('--search-filters', type=json.loads, help='Dictionary input as JSON string', default="{}", action='append')
arg.add_argument('--sort-criteria', type=str, help="What property to sort by")
arg.add_argument('--reverse',action='store_true',help="Reverses the search")
arg.add_argument('--settings',help='path to a .json file, that overwrides all arguments', default="")
arg.add_argument('--build-settings', help="Creates a new settings file", default="")
arg.add_argument('--simplify', help="Will simplify the message output", action='store_true')
arg.add_argument('--display-keys', help="Shows the valid keys in the logfile", action="store_true")


log_dir = "C:\\windows\\system32\\winevt\Logs"
log_dir =  "C:\\Users\\Intern\\test_logs"

search_criteria = ["Name", {"EventID" : None}, {"SystemTime" : None}, "Level"]
sort_criteria = {"SystemTime" : False} # Key, Is reversed?

simplify_message = False
display_keys = False
# search_for = ["Application.evtx", "Setup.evtx", "System.evtx"]

def main():
    files = [os.path.join(log_dir,f) for f in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, f)) and f.endswith(".evtx")]
    if log_dir.endswith(".evtx"): files = [log_dir]

    for f in files:
        print(f)

        ps = powershell_evtx(f)

        results = []
        parser = PyEvtxParser(f)
        json_record = list(parser.records_json())
        for record in range(len(json_record)):
            rc = parse_record(json_record[record])
            msg = {"Message" : "null"}
            if not ps[record]['Message'] is None:
                msg = ps[record]['Message']
                if not simplify_message:
                    msg = ps[record]['Message'].replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').strip()
                msg = {"Message": msg}
            rc.append(msg)
            results.append(rc)
        print(results)
        results = sorted(results, key=cmp_to_key(compare), reverse=next(iter(sort_criteria.values()), False))
        for result in results: 
            for value in result: print(value)
            print("-"*80)
        dict_arrays_to_csv(results, f[:-5] + ".csv")


def powershell_evtx(f, max_events=10000):
    ps_command = f'''
    Get-WinEvent -Path "{f}" -MaxEvents {max_events} | 
    Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName | 
    ConvertTo-Json -Depth 3
    '''

    completed = subprocess.run(
        ["powershell", "-Command", ps_command],
        capture_output=True, text=True
    )

    if completed.returncode != 0:
        raise Exception(f"PowerShell error: {completed.stderr}")
    try:
        data = json.loads(completed.stdout)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError as e:
        print("Failed to parse JSON from PowerShell output.")
        raise e

def dict_arrays_to_csv(data, filename):
    # print("-"*1000)
    # print(data[:10])
    all_keys = set()
    valid_rows = []

    for row in data:
        flat_row = {}
        brk = False
        for d in row:
            if not d or brk:
                brk = True
                continue
            flat_row.update(d)
        

        # Skip row if any value is blank string
        # if any((v is None) or (isinstance(v, str) and v.strip() == "") for v in flat_row.values()):
        #     continue
        valid_rows.append(flat_row)
        all_keys.update(flat_row.keys())

    all_keys = sorted(all_keys)

    # Write to CSV
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_keys)
        writer.writeheader()
        for row in valid_rows:
            writer.writerow({key: row.get(key, "") for key in all_keys})

def compare(item1, item2):
    if item1 is None or item2 is None or not sort_criteria:
        return 0

    # Get the key to sort by
    sort_key = next(iter(sort_criteria.keys()), None)
    if sort_key is None:
        return 0

    # Extract comparison values
    def extract_value(item):
        for entry in item:
            if entry and sort_key in entry:
                return entry[sort_key]
        return None

    val1 = extract_value(item1)
    val2 = extract_value(item2)

    # Handle None values
    if val1 is None or val2 is None:
        return 0

    return (val1 > val2) - (val1 < val2)



def parse_record(record):
    data = json.loads(record["data"])
    if display_keys:
        print(recursive_get_keys(data))
    search_results = []
    for i in search_criteria:
        result = recursive_tree_search(data, i)
        search_results.append(result)
    return search_results

def recursive_tree_search(root, param):
    ret = {}

    if isinstance(root, dict):
        for key in root:
            # If param is a dict, match key and optionally its value
            if isinstance(param, dict):
                for match_key, match_val in param.items():
                    if key == match_key and (match_val is None or root[key] == match_val):
                        if root[key] == None: root[key] == "null"
                        ret[key] = root[key]
                        return ret
            else:
                # If param is just a string, match the key
                if key == param:
                    ret[key] = root[key]
                    return ret

            # Recursively search in the value
            child = recursive_tree_search(root[key], param)
            if child:
                ret[key] = child

    # Post-process: if any value in ret is a dict, return the nested one (like your original intent)
    for key in list(ret.keys()):
        if isinstance(ret[key], dict):
            return ret[key]

    return ret


def recursive_get_keys(root):
    ret = []
    if type(root) == dict:
        for i in root.keys():
            ret.append(i)
            children = recursive_get_keys(root[i])
            for child in children: ret.append(child)
    return ret

def parse_arguments():
    global log_dir
    global search_criteria
    global sort_criteria
    global simplify_message
    global display_keys
    args = arg.parse_args()
    log_dir = args.log_dir

    settingspath = args.settings
    if args.build_settings != "":
        with open(args.build_settings, "w") as file:
           file.write('''{
"filter" : ["Name", "SystemTime", "EventID"],
    "search_criteria" : [
        {"Name" : null}
    ],
    "sort_criteria" : "SystemTime",
    "reverse" : false,
    "simplify" : false
}''') 

    if type(args.search_filters) == dict:
        if args.search_filters != {}:
            search_criteria = [args.search_filters]
        else:
            search_criteria = []
    else:
        search_criteria = args.search_filters
    keys = [list(d.keys())[0] for d in search_criteria]
    if type(args.filters) == str:
        filters = [args.filters]
    else:
        filters = args.filters
    for i in filters:
        if i in keys: continue
        search_criteria.append(i)
    
    simplify_message = args.simplify
    display_keys = args.display_keys
    
    sort_criteria = {args.sort_criteria : args.reverse}

    if settingspath.endswith(".json"):
        with open(settingspath) as file:
            settings = json.load(file)
            if settings["search_criteria"]:
                search_criteria = settings["search_criteria"]
            keys = [list(d.keys())[0] for d in search_criteria]
            if settings["filter"]:
                f = settings["filter"]
                for fi in f:
                    if fi in keys: continue
                    search_criteria.append(fi)
            
            if settings["sort_criteria"]:
                sort_criteria = {settings["sort_criteria"] : settings["reverse"]}
            
            simplify_message = settings["simplify"]




parse_arguments()
main()