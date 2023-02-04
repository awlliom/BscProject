import json
import argparse
import matplotlib
import re
import os
import sys
import re
import json
import pandas
import numpy as np
import csv
import matplotlib.pyplot as plt

tools = ["slither", "confuzzius", "mythril", "manticore", "conkas"]

# securify_bug_codes = [{'bug': 'Unhandled-Exceptions', 'codes': ['UnhandledException']}, {'bug': 'TOD', 'codes': ['TODAmount', 'TODReceiver', 'TODTransfer']},
#                       {'bug': 'Unchecked-Send', 'codes': ['UnrestrictedEtherFlow']}, {'bug': 'Re-entrancy', 'codes': ['DAOConstantGas', 'DAO']}]
# mythril_bug_codes = [{'bug': 'Unhandled-Exceptions', 'codes': ['Unchecked Call Return Value']}, {'bug': 'Timestamp-Dependency', 'codes': ['Dependence on predictable environment variable']},
#                      {'bug': 'Overflow-Underflow', 'codes': ['Integer Underflow', 'Integer Overflow']}, {'bug': 'tx.origin', 'codes': [
#                          'Use of tx.origin']}, {'bug': 'Unchecked-Send', 'codes': ['Unprotected Ether Withdrawal']},
#                      {'bug': 'Re-entrancy', 'codes': ['External Call To User-Supplied Address', 'External Call To Fixed Address', 'State change after external call']}]
# slither_bug_codes = [{'bug': 'Unhandled-Exceptions', 'codes': ['unchecked-send', 'unchecked-lowlevel']}, {'bug': 'Timestamp-Dependency', 'codes': ['timestamp']},
#                      {'bug': 'tx.origin', 'codes': ['tx-origin']}, {'bug': 'Re-entrancy', 'codes': ['reentrancy-benign', 'reentrancy-eth', 'reentrancy-unlimited-gas', 'reentrancy-no-eth']}]
# smartcheck_bug_codes = [{'bug': 'Unhandled-Exceptions', 'codes': ['SOLIDITY_UNCHECKED_CALL']}, {'bug': 'Timestamp-Dependency', 'codes': ['SOLIDITY_EXACT_TIME', 'VYPER_TIMESTAMP_DEPENDENCE']},
#                         {'bug': 'Overflow-Underflow', 'codes': ['SOLIDITY_UINT_CANT_BE_NEGATIVE']}, {'bug': 'tx.origin', 'codes': ['SOLIDITY_TX_ORIGIN']}, {'bug': 'Re-entrancy', 'codes': ['SOLIDITY_ETRNANCY']}]
# manticore_bug_codes = [{'bug': 'Re-entrancy', 'codes': ['Potential reentrancy vulnerability', 'Reachable ether leak to sender']}, {'bug': 'Overflow-Underflow', 'codes': [
#     'Unsigned integer overflow at ADD instruction', 'Signed integer overflow at ADD instruction', 'Unsigned integer overflow at SUB instruction', 'Signed integer overflow at SUB instruction']}]
# conkas_bug_codes = [{'bug': 'Overflow-Underflow', 'codes': ['Integer Underflow', 'Integer Overflow']}, {'bug': 'Re-entrancy', 'codes': ['Reentrancy']}, {'bug': 'Timestamp-Dependency',
#                                                                                                                                                         'codes': ['Time Manipulation']}, {'bug': 'TOD', 'codes': ['Transaction Ordering Dependence']}, {'bug': 'Unhandled-Exceptions', 'codes': ['Unchecked Low Level Call']}]

oracle = {}
vulnerability_type_count = {}
vulnerability_mapping = {}
contract_vulnerabilities = {}
precisions = {}
contract_precisions = {}
vulnerability_stat = {}
tool_stat = {}
output = {}
stats = {}
stats['slither'] = {}
stats['confuzzius'] = {}
stats['manticore'] = {}
stats['mythril'] = {}
stats['conkas'] = {}


slither_false_neg = 0
slither_false_type = 0
slither_false_pos = 0
slither_bugs = {'denial_service': 0, 'access_control': 0, 'arithmetic': 0, 'reentrancy': 0,
                'unchecked_low_calls': 0, 'bad_randomness': 0, 'front_running': 0, 'time_manipulation': 0, 'other': 0}

# parser = argparse.ArgumentParser()
# parser.add_argument('indir', default='./outputs', type=str, help='')

# parsed = parser.parse_args()

#indir = parsed.indir


indir = 'outputs'
total_vul_number = 0
con_dir = 'my_contracts'

with open(os.path.join('./vulnerabilities.json')) as f:
    vuls = json.load(f)
    for con in vuls:
        oracle[con['name'].replace('.sol', '')] = con

nb_tagged_vulnerabilities = 0
for contract in oracle:
    for vuln in oracle[contract]['vulnerabilities']:
        if vuln['category'] not in vulnerability_type_count:
            vulnerability_type_count[vuln['category']] = 0
        vulnerability_type_count[vuln['category']] += 1
        nb_tagged_vulnerabilities += 1

with open('./vulnerabilities_mapping.csv') as fd:
    header = fd.readline().strip().split(',')
    line = fd.readline()
    while line:
        v = line.strip().split(',')
        index = -1
        if 'TRUE' in v:
            index = v.index('TRUE')
        if index > -1:
            vulnerability_mapping[v[1]] = header[index]
        line = fd.readline()
categories = sorted(list(set(vulnerability_mapping.values())))
categories.remove('Ignore')

cons = []
files = [f for f in os.listdir(con_dir) if (os.path.isfile(os.path.join(
    con_dir, f)) and f.endswith('.sol'))]
for f in files:
    contract = f.replace('.sol', '')
    total_vul_number += len(oracle[contract]['vulnerabilities'])
    cons.append(contract)

vul_type_count = {}
nb_tagged_vuls = 0
contract_vuls = {key: oracle[key] for key in oracle if key in cons}
for contract in contract_vuls:
    for vuln in contract_vuls[contract]['vulnerabilities']:
        if vuln['category'] not in vul_type_count:
            vul_type_count[vuln['category']] = 0
        vul_type_count[vuln['category']] += 1
        nb_tagged_vuls += 1

for category in categories:
    precisions[category] = {}

stats['slither']['times'] = []
files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('slither_') and f.endswith('.time'))]
for f in files:
    with open(os.path.join(indir, f), 'r') as f:
        stats['slither']['times'].append(float(f.read()))

stats['confuzzius']['times'] = []
files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('confuzzius_') and f.endswith('.time'))]
for f in files:
    with open(os.path.join(indir, f), 'r') as f:
        stats['confuzzius']['times'].append(float(f.read()))

stats['conkas']['times'] = []
files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('conkas_') and f.endswith('.time'))]
for f in files:
    with open(os.path.join(indir, f), 'r') as f:
        stats['conkas']['times'].append(float(f.read()))

stats['mythril']['times'] = []
files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('mythril_') and f.endswith('.time'))]
for f in files:
    with open(os.path.join(indir, f), 'r') as f:
        stats['mythril']['times'].append(float(f.read()))

stats['manticore']['times'] = []
files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('manticore_') and f.endswith('.time'))]
for f in files:
    with open(os.path.join(indir, f), 'r') as f:
        stats['manticore']['times'].append(float(f.read()))

stats['slither']['timeouts'] = 0
stats['slither']['errors'] = 0
stats['slither']['percontract'] = 0


files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('slither_') and f.endswith('.time'))]
for f in files:
    time = open(os.path.join(indir, f), "r").read()
    if float(time) >= 119:
        stats['slither']['timeouts'] = stats['slither']['timeouts'] + 1

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('slither_') and f.endswith('.err'))]
for f in files:
    cissues = {}
    errors = open(os.path.join(indir, f), "r").read()
    if ":Traceback" in errors:
        stats['slither']['errors'] = stats['slither']['errors'] + 1

stats['confuzzius']['timeouts'] = 0
stats['confuzzius']['errors'] = 0
stats['confuzzius']['percontract'] = 0

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('confuzzius_') and f.endswith('.time'))]
for f in files:
    time = open(os.path.join(indir, f), "r").read()
    if float(time) >= 119:
        stats['confuzzius']['timeouts'] = stats['confuzzius']['timeouts'] + 1

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('confuzzius_') and f.endswith('.err'))]
for f in files:
    cissues = {}
    errors = open(os.path.join(indir, f), "r").read()
    if ":Traceback" in errors:
        stats['confuzzius']['errors'] = stats['confuzzius']['errors'] + 1

stats['conkas']['timeouts'] = 0
stats['conkas']['errors'] = 0
stats['conkas']['percontract'] = 0

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('conkas_') and f.endswith('.time'))]
for f in files:
    time = open(os.path.join(indir, f), "r").read()
    if float(time) >= 119:
        stats['conkas']['timeouts'] = stats['conkas']['timeouts'] + 1

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('conkas_') and f.endswith('.err'))]
for f in files:
    cissues = {}
    errors = open(os.path.join(indir, f), "r").read()
    if ":Traceback" in errors:
        stats['conkas']['errors'] = stats['conkas']['errors'] + 1

stats['mythril']['timeouts'] = 0
stats['mythril']['errors'] = 0
stats['mythril']['percontract'] = 0

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('mythril_') and f.endswith('.time'))]
for f in files:
    time = open(os.path.join(indir, f), "r").read()
    if float(time) >= 119:
        stats['mythril']['timeouts'] = stats['mythril']['timeouts'] + 1

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('mythril_') and f.endswith('.err'))]
for f in files:
    cissues = {}
    errors = open(os.path.join(indir, f), "r").read()
    if ":Traceback" in errors:
        stats['mythril']['errors'] = stats['mythril']['errors'] + 1

stats['manticore']['timeouts'] = 0
stats['manticore']['errors'] = 0
stats['manticore']['percontract'] = 0

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('manticore_') and f.endswith('.time'))]
for f in files:
    time = open(os.path.join(indir, f), "r").read()
    if float(time) >= 119:
        stats['manticore']['timeouts'] = stats['manticore']['timeouts'] + 1

files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
    indir, f)) and f.startswith('manticore_') and f.endswith('.err'))]
for f in files:
    cissues = {}
    errors = open(os.path.join(indir, f), "r").read()
    if ":Traceback" in errors:
        stats['manticore']['errors'] = stats['manticore']['errors'] + 1


def add_vul(contract, tool, vulnerability, lines):
    original_vulnerability = vulnerability
    vulnerability = vulnerability.strip().lower().title().replace('_', ' ').replace(
        '.', '').replace('Solidity ', '').replace('Potentially ', '')
    vulnerability = re.sub(r' At Instruction .*', '', vulnerability)

    category = 'unknown'
    if original_vulnerability in vulnerability_mapping:
        category = vulnerability_mapping[original_vulnerability]
    else:
        print(original_vulnerability)
    if category == 'Ignore' or category == 'unknown':
        return

    if tool not in precisions[category]:
        precisions[category][tool] = set()

    if tool not in contract_precisions:
        contract_precisions[tool] = []

    if category not in vulnerability_stat:
        vulnerability_stat[category] = 0
    if tool not in tool_stat:
        tool_stat[tool] = {}
    if category not in tool_stat[tool]:
        tool_stat[tool][category] = 0
        #print("%s\t%s" % (tool, vulnerability_original))

    expected = oracle[contract]
    for vuln in expected['vulnerabilities']:
        if lines is not None:
            for line in lines:
                if line in vuln['lines'] and category == vuln['category']:
                    vuln = {
                        'contract': contract,
                        'category': vuln['category'],
                        'lines': vuln['lines']
                    }
                    if vuln not in precisions[category][tool]:
                        precisions[category][tool].append(vuln)
                    if contract not in contract_precisions[tool]:
                        contract_precisions[tool].append(contract)
                    break

    if contract not in contract_vulnerabilities:
        contract_vulnerabilities[contract] = []

    if category not in contract_vulnerabilities[contract]:
        contract_vulnerabilities[contract].append(category)

    tool_stat[tool][category] += 1
    if contract not in output:
        output[contract] = {}
    if 'tools' not in output[contract]:
        output[contract]['tools'] = {}
    if tool not in output[contract]['tools']:
        output[contract]['tools'][tool] = {}
    if 'categories' not in output[contract]['tools'][tool]:
        output[contract]['tools'][tool]['categories'] = {}
    if category not in output[contract]['tools'][tool]['categories']:
        output[contract]['tools'][tool]['categories'][category] = 0
        vulnerability_stat[category] += 1
    output[contract]['tools'][tool]['categories'][category] += 1
    if 'vulnerabilities' not in output[contract]['tools'][tool]:
        output[contract]['tools'][tool]['vulnerabilities'] = {}
    if original_vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
        output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] = 0
    output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] += 1


for tool in tools:

    # slither
    if tool == 'slither':
        files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
            indir, f)) and f.startswith('slither_') and f.endswith('.json'))]
        for f in files:
            contract = f.replace('slither_', '').replace('.json', '')
            log = json.load(open(os.path.join(indir, f)))
            expected = oracle[contract]
            # print(expected)
            if not log['success'] == True:
                continue
            for vuln in log['results']['detectors']:
                vulnerability = vuln['check'].strip()
                category = 'unknown'
                if vulnerability in vulnerability_mapping:
                    category = vulnerability_mapping[vulnerability]
                if category == 'Ignore' or category == 'unknown':
                    continue
                if tool not in precisions[category]:
                    precisions[category][tool] = []
                if tool not in contract_precisions:
                    contract_precisions[tool] = []
                if category not in vulnerability_stat:
                    vulnerability_stat[category] = 0
                if tool not in tool_stat:
                    tool_stat[tool] = {}
                if category not in tool_stat[tool]:
                    tool_stat[tool][category] = 0
                lines = None
                if len(vuln['elements']) > 0 and 'source_mapping' in vuln['elements'][0] and len(vuln['elements'][0]['source_mapping']['lines']) > 0:
                    lines = vuln['elements'][0]['source_mapping']['lines']
                for vul in expected['vulnerabilities']:
                    if line is not None:
                        for line in lines:
                            if line in vul['lines'] and category == vul['category']:
                                add_vuln = {
                                    'contract': contract,
                                    'lines': lines
                                }
                                vul_not_exist = True
                                for vs in precisions[category][tool]:
                                    if vs['contract'] == add_vuln['contract'] and not set(add_vuln['lines']).isdisjoint(vs['lines']):
                                        vul_not_exist = False
                                        break
                                # if add_vuln not in precisions[category][tool]:
                                #     precisions[category][tool].append(add_vuln)
                                #     stats['slither']['percontract'] += 1
                                if vul_not_exist:
                                    precisions[category][tool].append(add_vuln)
                                    stats['slither']['percontract'] += 1
                                if contract not in contract_precisions[tool]:
                                    contract_precisions[tool].append(contract)
                                break
                if contract not in contract_vulnerabilities:
                    contract_vulnerabilities[contract] = []

                if category not in contract_vulnerabilities[contract]:
                    contract_vulnerabilities[contract].append(category)

                tool_stat[tool][category] += 1
                if contract not in output:
                    output[contract] = {}
                if 'tools' not in output[contract]:
                    output[contract]['tools'] = {}
                if tool not in output[contract]['tools']:
                    output[contract]['tools'][tool] = {}
                if 'categories' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['categories'] = {}
                if category not in output[contract]['tools'][tool]['categories']:
                    output[contract]['tools'][tool]['categories'][category] = 0
                    vulnerability_stat[category] += 1
                output[contract]['tools'][tool]['categories'][category] += 1
                if 'vulnerabilities' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['vulnerabilities'] = {}
                if vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
                    output[contract]['tools'][tool]['vulnerabilities'][vulnerability] = 0
                output[contract]['tools'][tool]['vulnerabilities'][vulnerability] += 1

    # confuzzius
    if tool == 'confuzzius':
        files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
            indir, f)) and f.startswith('confuzzius_') and f.endswith('.json'))]
        for f in files:
            contract = f.replace('confuzzius_', '').replace('.json', '')
            log = json.load(open(os.path.join(indir, f)))
            expected = oracle[contract]
            # print(expected)
            for ans in log.values():
                if not ans['errors']:
                    continue
                for vuln in ans['errors']:
                    for vulnerability in ans['errors'][vuln]:
                        vul_type = vulnerability['type']
                        category = 'unknown'
                        if vul_type in vulnerability_mapping:
                            category = vulnerability_mapping[vul_type]
                        if category == 'Ignore' or category == 'unknown':
                            continue
                        if tool not in precisions[category]:
                            precisions[category][tool] = []
                        if tool not in contract_precisions:
                            contract_precisions[tool] = []
                        if category not in vulnerability_stat:
                            vulnerability_stat[category] = 0
                        if tool not in tool_stat:
                            tool_stat[tool] = {}
                        if category not in tool_stat[tool]:
                            tool_stat[tool][category] = 0
                        for vul in expected['vulnerabilities']:
                            if category == vul['category'] and vulnerability['line'] in vul['lines']:
                                add_vuln = {
                                    'contract': contract,
                                    'lines': int(vulnerability['line'])
                                }
                                if add_vuln not in precisions[category][tool]:
                                    precisions[category][tool].append(add_vuln)
                                    stats['confuzzius']['percontract'] += 1
                                if contract not in contract_precisions[tool]:
                                    contract_precisions[tool].append(contract)
                                break
                        if contract not in contract_vulnerabilities:
                            contract_vulnerabilities[contract] = []

                        if category not in contract_vulnerabilities[contract]:
                            contract_vulnerabilities[contract].append(category)

                        tool_stat[tool][category] += 1
                        if contract not in output:
                            output[contract] = {}
                        if 'tools' not in output[contract]:
                            output[contract]['tools'] = {}
                        if tool not in output[contract]['tools']:
                            output[contract]['tools'][tool] = {}
                        if 'categories' not in output[contract]['tools'][tool]:
                            output[contract]['tools'][tool]['categories'] = {}
                        if category not in output[contract]['tools'][tool]['categories']:
                            output[contract]['tools'][tool]['categories'][category] = 0
                            vulnerability_stat[category] += 1
                        output[contract]['tools'][tool]['categories'][category] += 1
                        if 'vulnerabilities' not in output[contract]['tools'][tool]:
                            output[contract]['tools'][tool]['vulnerabilities'] = {}
                        if vul_type not in output[contract]['tools'][tool]['vulnerabilities']:
                            output[contract]['tools'][tool]['vulnerabilities'][vul_type] = 0
                        output[contract]['tools'][tool]['vulnerabilities'][vul_type] += 1

    # conkas
    if tool == 'conkas':
        files = [f for f in os.listdir(indir) if (os.path.isfile(
            os.path.join(indir, f)) and f.startswith('conkas_') and f.endswith('.out'))]
        for f in files:
            contract = f.replace('conkas_', '').replace('.out', '')
            expected = oracle[contract]
            with open(os.path.join(indir, f), 'r') as ff:
                out = ff.readlines()
            for res in out:
                if not res.startswith('Vulnerability:'):
                    continue
                vulnerability = res.split('Vulnerability: ')[1].split('.')[0]
                line_number = res.split('Line number: ')[1].split('.')[0]
                category = 'unknown'
                if vulnerability in vulnerability_mapping:
                    category = vulnerability_mapping[vulnerability]
                if category == 'Ignore' or category == 'unknown':
                    continue
                if tool not in precisions[category]:
                    precisions[category][tool] = []
                if tool not in contract_precisions:
                    contract_precisions[tool] = []
                if category not in vulnerability_stat:
                    vulnerability_stat[category] = 0
                if tool not in tool_stat:
                    tool_stat[tool] = {}
                if category not in tool_stat[tool]:
                    tool_stat[tool][category] = 0
                for vul in expected['vulnerabilities']:
                    if category == vul['category'] and int(line_number) in vul['lines']:
                        add_vuln = {
                            'contract': contract,
                            'lines': int(line_number)
                        }
                        if add_vuln not in precisions[category][tool]:
                            precisions[category][tool].append(add_vuln)
                            stats['conkas']['percontract'] += 1
                        if contract not in contract_precisions[tool]:
                            contract_precisions[tool].append(contract)
                        break
                if contract not in contract_vulnerabilities:
                    contract_vulnerabilities[contract] = []

                if category not in contract_vulnerabilities[contract]:
                    contract_vulnerabilities[contract].append(category)

                tool_stat[tool][category] += 1
                if contract not in output:
                    output[contract] = {}
                if 'tools' not in output[contract]:
                    output[contract]['tools'] = {}
                if tool not in output[contract]['tools']:
                    output[contract]['tools'][tool] = {}
                if 'categories' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['categories'] = {}
                if category not in output[contract]['tools'][tool]['categories']:
                    output[contract]['tools'][tool]['categories'][category] = 0
                    vulnerability_stat[category] += 1
                output[contract]['tools'][tool]['categories'][category] += 1
                if 'vulnerabilities' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['vulnerabilities'] = {}
                if vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
                    output[contract]['tools'][tool]['vulnerabilities'][vulnerability] = 0
                output[contract]['tools'][tool]['vulnerabilities'][vulnerability] += 1

    # mythril
    if tool == 'mythril':
        files = [f for f in os.listdir(indir) if (os.path.isfile(os.path.join(
            indir, f)) and f.startswith('mythril_') and f.endswith('.json'))]
        for f in files:
            contract = f.replace('mythril_', '').replace('.json', '')
            if os.stat(os.path.join(indir, f)).st_size == 1:
                continue
            log = json.load(open(os.path.join(indir, f)))
            expected = oracle[contract]
            # print(expected)
            if not log['success'] == True:
                continue
            for issue in log['issues']:
                vulnerability = issue['title'].strip()
                category = 'unknown'
                if vulnerability in vulnerability_mapping:
                    category = vulnerability_mapping[vulnerability]
                if category == 'Ignore' or category == 'unknown':
                    continue
                if tool not in precisions[category]:
                    precisions[category][tool] = []
                if tool not in contract_precisions:
                    contract_precisions[tool] = []
                if category not in vulnerability_stat:
                    vulnerability_stat[category] = 0
                if tool not in tool_stat:
                    tool_stat[tool] = {}
                if category not in tool_stat[tool]:
                    tool_stat[tool][category] = 0
                if not ('lineno' in issue.keys()):
                    continue
                lines = issue['lineno']
                for vul in expected['vulnerabilities']:
                    if category == vul['category'] and int(lines) in vul['lines']:
                        add_vuln = {
                            'contract': contract,
                            'lines': int(lines)
                        }
                        if add_vuln not in precisions[category][tool]:
                            precisions[category][tool].append(add_vuln)
                            stats['mythril']['percontract'] += 1
                        if contract not in contract_precisions[tool]:
                            contract_precisions[tool].append(contract)
                        break
                if contract not in contract_vulnerabilities:
                    contract_vulnerabilities[contract] = []

                if category not in contract_vulnerabilities[contract]:
                    contract_vulnerabilities[contract].append(category)

                tool_stat[tool][category] += 1
                if contract not in output:
                    output[contract] = {}
                if 'tools' not in output[contract]:
                    output[contract]['tools'] = {}
                if tool not in output[contract]['tools']:
                    output[contract]['tools'][tool] = {}
                if 'categories' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['categories'] = {}
                if category not in output[contract]['tools'][tool]['categories']:
                    output[contract]['tools'][tool]['categories'][category] = 0
                    vulnerability_stat[category] += 1
                output[contract]['tools'][tool]['categories'][category] += 1
                if 'vulnerabilities' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['vulnerabilities'] = {}
                if vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
                    output[contract]['tools'][tool]['vulnerabilities'][vulnerability] = 0
                output[contract]['tools'][tool]['vulnerabilities'][vulnerability] += 1

    # manticore
    if tool == 'manticore':
        mcore = 'mcore_res'
        files = []
        directories = [f for f in os.listdir(indir) if (os.path.isdir(os.path.join(
            indir, f)) and f.startswith('manticore_'))]
        for dir in directories:
            for f in os.listdir(os.path.join(indir, dir, mcore)):
                if f == 'global.findings':
                    files.append(os.path.join(indir, dir, mcore, f))
                    break
        contract_bugs = []
        for f in files:
            contract = f.replace('manticore_', '').replace(
                '/global.findings', '').replace('outputs/', '').replace('/mcore_res', '')
            #log = json.load(open(os.path.join(indir, f)))
            expected = oracle[contract]
            # print(expected)
            with open(f, 'r') as ff:
                out = ff.readlines()
            current_vul = None
            for line in out:
                if len(line) == 0:
                    continue
                if line[0] == '-':
                    if current_vul is not None:
                        contract_bugs.append(current_vul)
                    current_vul = {
                        'name': line[1:-2].strip(),
                        'line': -1,
                        'code': None
                    }
                elif current_vul is not None and line[:4] == '    ':
                    index = line[4:].rindex('  ') + 4
                    current_vul['line'] = int(line[4:index])
                    current_vul['code'] = line[index:].strip()
            if current_vul is not None:
                contract_bugs.append(current_vul)
            for bug in contract_bugs:
                vulnerability = bug['name']
                category = 'unknown'
                if vulnerability in vulnerability_mapping:
                    category = vulnerability_mapping[vulnerability]
                if category == 'Ignore' or category == 'unknown':
                    continue
                if tool not in precisions[category]:
                    precisions[category][tool] = []
                if tool not in contract_precisions:
                    contract_precisions[tool] = []
                if category not in vulnerability_stat:
                    vulnerability_stat[category] = 0
                if tool not in tool_stat:
                    tool_stat[tool] = {}
                if category not in tool_stat[tool]:
                    tool_stat[tool][category] = 0
                for vul in expected['vulnerabilities']:
                    if category == vul['category'] and current_vul['line'] in vul['lines']:
                        add_vuln = {
                            'contract': contract,
                            'lines': int(current_vul['line'])
                        }
                        if add_vuln not in precisions[category][tool]:
                            precisions[category][tool].append(add_vuln)
                            stats['manticore']['percontract'] += 1
                        if contract not in contract_precisions[tool]:
                            contract_precisions[tool].append(contract)
                        break
                if contract not in contract_vulnerabilities:
                    contract_vulnerabilities[contract] = []

                if category not in contract_vulnerabilities[contract]:
                    contract_vulnerabilities[contract].append(category)

                tool_stat[tool][category] += 1
                if contract not in output:
                    output[contract] = {}
                if 'tools' not in output[contract]:
                    output[contract]['tools'] = {}
                if tool not in output[contract]['tools']:
                    output[contract]['tools'][tool] = {}
                if 'categories' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['categories'] = {}
                if category not in output[contract]['tools'][tool]['categories']:
                    output[contract]['tools'][tool]['categories'][category] = 0
                    vulnerability_stat[category] += 1
                output[contract]['tools'][tool]['categories'][category] += 1
                if 'vulnerabilities' not in output[contract]['tools'][tool]:
                    output[contract]['tools'][tool]['vulnerabilities'] = {}
                if vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
                    output[contract]['tools'][tool]['vulnerabilities'][vulnerability] = 0
                output[contract]['tools'][tool]['vulnerabilities'][vulnerability] += 1


print("slither:")
print("time:", np.mean(stats['slither']['times']),
      np.std(stats['slither']['times']))
print("stats", stats['slither']['percontract'],
      float(stats['slither']['errors']) / len(files) * 100, float(stats['slither']['timeouts'])/1000 * 100)

print("manticore:")
print("time:", np.mean(stats['manticore']['times']),
      np.std(stats['manticore']['times']))
print("stats", stats['manticore']['percontract'],
      float(stats['manticore']['errors']) / len(files) * 100, float(stats['manticore']['timeouts'])/1000 * 100)

print("mythril:")
print("time:", np.mean(stats['mythril']['times']),
      np.std(stats['mythril']['times']))
print("stats", stats['mythril']['percontract'],
      float(stats['mythril']['errors']) / len(files) * 100, float(stats['mythril']['timeouts'])/1000 * 100)

print("conkas:")
print("time:", np.mean(stats['conkas']['times']),
      np.std(stats['conkas']['times']))
print("stats", stats['conkas']['percontract'],
      float(stats['conkas']['errors']) / len(files) * 100, float(stats['conkas']['timeouts'])/1000 * 100)

print("confuzzius:")
print("time:", np.mean(stats['confuzzius']['times']),
      np.std(stats['confuzzius']['times']))
print("stats", stats['confuzzius']['percontract'],
      float(stats['confuzzius']['errors']) / len(files) * 100, float(stats['confuzzius']['timeouts'])/1000 * 100)


print(precisions)
print('=================')
print(contract_precisions)
print("_____________________________")
print('total: ', total_vul_number)
print("\n# Accuracy\n")


total_precision = []
index_vulnerability = 1
line = '|  Category           |'
for tool in sorted(tools):
    line += ' {:^11} |'.format(tool.title())
line += ' {:^11} |'.format('Total')
print(line)

line = "| ------------------- |"
for tool in tools:
    line += ' {:-<11} |'.format('-')
line += ' {:-<11} |'.format('')
print(line)

total_tools = {}
for category in categories:
    if category == 'unchecked_low_level_calls':
        category = 'unchecked_calls'
    line = "| {:19} |".format(category.title().replace('_', ' '))
    if category == 'unchecked_calls':
        category = 'unchecked_low_level_calls'
    total_detection_tool = 0
    total_category_precision = []
    for tool in sorted(tools):
        found = 0
        if tool not in total_tools:
            total_tools[tool] = 0
        if tool in precisions[category]:
            found = len(precisions[category][tool])
            for vuln in precisions[category][tool]:
                if vuln not in total_precision:
                    total_precision.append(vuln)
                if vuln not in total_category_precision:
                    total_category_precision.append(vuln)
        total_tools[tool] += found
        expected = vul_type_count[category]

        total_identified = 0
        if category in tool_stat[tool]:
            total_identified = tool_stat[tool][category]
        total_detection_tool += total_identified
        line += "  {:>5} {:3}% |".format("{:}/{:}".format(
            found, expected), round(found*100/expected))
    line += "  {:2}/{:2} {:3}% |".format(len(total_category_precision), vul_type_count[category], round(
        len(total_category_precision)*100/vul_type_count[category]))
    print(line)
    index_vulnerability += 1
line = "| {:19} |".format('Total')
for tool in sorted(tools):
    found = total_tools[tool]
    expected = nb_tagged_vuls
    line += "  {:2}/{:2} {:3}% |".format(found,
                                         expected, round(found*100/expected))
line += "  {:2}/{:2} {:3}% |".format(len(total_precision), nb_tagged_vuls,
                                     round(len(total_precision)*100/nb_tagged_vuls))
print(line)

print("\n# Combine tools ")

tool_ability = {}
for category in categories:
    for tool in precisions[category]:
        if tool not in tool_ability:
            tool_ability[tool] = []
        vulns = precisions[category][tool]
        for vuln in vulns:
            tool_ability[tool].append(vuln)

line = '| {:11} |'.format('')
for tool_a in sorted(tools):
    line += ' {:^11} |'.format(tool_a.title())
print(line)
line = '| {:-<11} |'.format('-')
for tool_a in sorted(tools):
    line += ' {:-<11} |'.format('-')
print(line)

for tool_a in sorted(tools):
    line = '| {:11} |'.format(tool_a.title())

    ability_a = tool_ability[tool_a]
    stop_number = True
    for tool_b in sorted(tools):
        if tool_a == tool_b or stop_number:
            line += ' {:11} |'.format('')
            if tool_a == tool_b:
                stop_number = False
            continue
        ability_b = [*tool_ability[tool_b]]
        if tool_b == 'slither':
            temp_ability_b = [*tool_ability[tool_b]]
            for vuln in ability_a:
                not_subset = True
                for v in temp_ability_b:
                    if vuln['contract'] == v['contract'] and vuln['lines'] in v['lines']:
                        not_subset = False
                        break
                if not_subset:
                    ability_b.append(vuln)
        else:
            for vuln in ability_a:
                if vuln not in ability_b:
                    ability_b.append(vuln)
        line += ' {:7} {:2}% |'.format("%d/%d" % (len(ability_b), nb_tagged_vuls),
                                       round(len(ability_b)*100/nb_tagged_vuls))
    print(line)


numbers = []
sticks = []
for tool in tools:
    numbers.append(np.mean(stats[tool]['times']))

plt.bar(range(len(numbers)), numbers)

plt.xlabel('Tool')
plt.ylabel('Time')
plt.title('Comparison of Time Mean')

plt.xticks(range(len(numbers)), tools)

plt.show()
