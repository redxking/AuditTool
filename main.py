'''
Author: Angelis Pseftis
Date: November 2022
'''

import argparse
import sys
import yaml
import logging
from os import path
from glob import glob
from ciscoconfparse import CiscoConfParse

# Set up logging
logging.basicConfig(filename='audit.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')

def print_rule_result(rule_data, rule_result, verbosity=0):
    if verbosity == 0:
        print(f"{rule_data['vuln_id']:<10} {rule_data['desc']:<62} {rule_result['success']}")
    elif verbosity == 1:
        print('----------------------------------------------------------------------')
        print(f"Vuln ID:     {rule_data['vuln_id']}")
        print(f"Severity:    {rule_data['severity']}")
        print(f"Description: {rule_data['desc']}")
        for k, v in rule_result['iter'].items():
            print(f'{k} objects:')
            for obj in v:
                print(f'  - {obj.text}')
        print(f'Success:     {rule_result["success"]}')
    elif verbosity == 2:
        obj_texts = ','.join('~'.join(line.text for line in v) for k, v in rule_result['iter'].items())
        print(f"{rule_data['vuln_id']},{rule_data['severity']},{rule_data['desc']},{rule_result['success']},{obj_texts}")

def check(parse, rule):
    if rule['check'].get('parent'):
        return _check_hier(parse, rule)
    return _check_global(parse, rule)

def _check_global(parse, rule):
    '''
    Finds all objects matching the search text, then counts the number of
    times the text was found in global config. If the match count equals
    the specified text_cnt, the test succeeds and the objects matched
    are considered pass objectives. Otherwise, the test fails and the
    objects matched are considered fail objects.

    Note that the "when" condition is never evaluated here.
    '''
    objs = parse.find_objects(rule['check']['text'])
    if len(objs) == rule['check']['text_cnt']:
        success = 'PASS'
        pass_objs = objs
        fail_objs = []
    else:
        success = 'FAIL'
        pass_objs = []
        fail_objs = objs
    return {'success': success, 'iter': {'pass': pass_objs, 'fail': fail_objs, 'na': []}}

def _check_hier(parse, rule):
    '''
    Get all subjects under the specified parent from the rule data. If
    "when" is a boolean True then the test is always performed. If "when" is
    a string, it is treated as a search regex to look for other child elements
    before running the test. For example, proxy-ARP disabled is only relevant
    when the interface has an IP address, so "ip(backslash)s+address" is a
    valid "when" condition.

    Similar to the global check, parents that have properly matching children
    are added to the pass list, and those that lack the proper match string
    are added to the fail list. Not applicable list contains elements where
    "when" was false (interfaces that don't have IPs don't care about whether
    proxy-ARP is enabled).
    '''
    pass_objs = []
    fail_objs = []
    na_objs = []
    parents = parse.find_objects(rule['check']['parent'])

    for parent in parents:
        when = isinstance(rule['check']['when'], bool) and rule['check']['when']
        if when or parent.re_search_children(rule['check']['when']):
            search = parent.re_search_children(rule['check']['text'])
            if len(search) == rule['check']['text_cnt']:
                pass_objs.append(parent)
            else:
                fail_objs.append(parent)
        else:
            na_objs.append(parent)

    if fail_objs:
        success = 'FAIL'
    elif na_objs and not pass_objs:
        success = 'N/A'
    else:
        success = 'PASS'
    return {'iter':{'pass': pass_objs, 'fail': fail_objs, 'na': na_objs}, 'success': success}


def process_args():
    '''
    Process command line arguments using argparse.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file', help='Configuration text file to scan', type=str)
    parser.add_argument('--stig', help='STIG to be used for the audit', type=str, default=None)
    parser.add_argument('--os_type', help='Operating system type: ios, xr, nxos, asa', type=str, default=None)
    parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2], help="0 for brief, 1 for details, 2 for CSV rows", default=0)
    parser.add_argument("-f", "--failonly", help="Print failures only", action="store_true")
    return parser.parse_args()


def main():
    args = process_args()
    try:
        parse = CiscoConfParse(args.config_file)
    except Exception as e:
        logging.error(f'Error while parsing the config file: {str(e)}')
        sys.exit(1)
    stigs = [args.stig] if args.stig else [obj.text.split(':')[1] for obj in parse.find_objects(r'!@#stig:\S+')]
    os_type = args.os_type if args.os_type else parse.find_objects(r'!@#type:\S+')[0].text.split(':')[1]
    rule_files = sorted(glob(f'rules/{os_type}/*.yml'))
    fail_cnt = 0
    for rule_file in rule_files:
        try:
            with open(rule_file, 'r') as stream:
                rule_data = yaml.safe_load(stream)
        except Exception as e:
            logging.error(f'Error while loading YAML data from file {rule_file}: {str(e)}')
            continue

        overlap = [v for v in stigs if v in rule_data.get('part_of_stig', [])]
        if not overlap:
            continue

        vuln_str = path.basename(rule_file).split('.')[0]
        rule_data.update({'vuln_id': vuln_str})

        rule_result = check(parse, rule_data)
        if rule_result['success'] == 'FAIL':
            fail_cnt += 1
            print_rule_result(rule_data, rule_result, args.verbosity)
        elif not args.failonly:
            print_rule_result(rule_data, rule_result, args.verbosity)

    sys.exit(fail_cnt)


if __name__ == '__main__':
    main()

