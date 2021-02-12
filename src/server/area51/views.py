# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import json

from . import area51
from flask import jsonify

def check_key_unique_value(objs, key, b_detail=False, found_strs = []):
    extracted = []
    for obj in objs:
        if type(obj[key]) is not list:
            extracted.append(obj[key])
        else:
            extracted.extend(obj[key])
    if found_strs:
        for subs in found_strs:
            extracted = [i for i in extracted if subs not in i]
    extracted_set = set(extracted)
    extracted_num = len(extracted_set)

    output = '{key} number={extracted_num}<br>'.format(key=key, extracted_num=extracted_num)
    if b_detail:
        for item in extracted_set:
            output += '&nbsp;&nbsp;&nbsp;&nbsp;' + str(item) + '<br>'
    return output


def dump_objs(objs):
    output = check_key_unique_value(objs, 'sid')
    output += check_key_unique_value(objs, 'gid')
    output += check_key_unique_value(objs, 'rev')
    output += check_key_unique_value(objs, 'action')
    output += check_key_unique_value(objs, 'classtype', True)
    output += check_key_unique_value(objs, 'msg')
    output += check_key_unique_value(objs, 'header')
    output += check_key_unique_value(objs, 'metadata', True, ['created_at', 'updated_at'])
    output += check_key_unique_value(objs, 'options', True, ['sid:', 'metadata:', 'msg:', 'content:', 'reference:'])
    for obj in objs:
        # output += json.dumps(obj) + '<br>'
        output += 'header: ' + obj['header'] + '<br>'
        output += 'metadata: ' + dump_list(obj['metadata']) + '<br>'
        output += 'options: ' + dump_list(obj['options']) + '<br>'
    return output

def dump_list(the_list):
    b_first = True
    output = '[<br>'
    for item in the_list:
        if not b_first:
            output += '<br>'
        else:
            b_first = False 
        output += '&nbsp;&nbsp;&nbsp;&nbsp;' + item
    output += ']<br>'
    return output

def construct_list(the_list):
    value = []
    for item in the_list:
        value.append(str(item))
    return value

def parse_rule(rule_file):
    from server.util.util_text_file import get_lines
    from suricataparser import parse_rule, parse_file
    s_ruleset_path = '/Users/huangstan/srv/data/' + 'rules/'

    ### read file in all_lines
    objs = []
    all_lines = get_lines(s_ruleset_path + rule_file)
    ### process all lines
    for line in all_lines:
        # if line[0] != '#':
        rule = parse_rule(line)
        if rule:
            if rule.enabled == True:
                obj = {}
                obj['sid'] = rule.sid
                obj['gid'] = rule._gid
                obj['rev'] = rule.rev
                obj['action'] = rule.action
                obj['classtype'] = rule.classtype
                obj['msg'] = rule.msg
                obj['header'] = rule.header
                obj['metadata'] = construct_list(rule.metadata)
                obj['options'] = construct_list(rule.options)
                objs.append(obj)
    return objs

@area51.after_app_request
def after_request(response):
    return response

# sanity check route
@area51.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify('pong!')

# suricata ruleset parser
@area51.route('/suricata-ruleset/<string:rule_file>', methods=['GET'])
def suricata_rule(rule_file):
    objs = parse_rule(rule_file)
    return dump_objs(objs)

# suricata ruleset parser
@area51.route('/suricata-rulesets', methods=['GET'])
def suricata_rulesets():
    from server.util.util_file import get_name_list_of_files

    ### get file list
    s_ruleset_path = '/Users/huangstan/srv/data/' + 'rules/'
    rule_files = get_name_list_of_files(s_ruleset_path)

    ### read file in all_lines
    objs = []
    for rule_file in rule_files:
        objs.extend(parse_rule(rule_file))
    return dump_objs(objs)
    