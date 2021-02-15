# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import json

from . import area51
from flask import jsonify

def find_str_in_list(the_str, the_list):
    for subs in the_list:
        if subs in the_str:
            return subs
    return None

def show_analyzed_unique_value(rules, key, b_detail=False, known_subkeys = [], ignored_strs = []):
    rulenum = len(rules)

    # extract values into extracted_vals and extracted_vals_set
    extracted_vals = []
    for rule in rules:
        if type(rule[key]) is not list:
            extracted_vals.append(rule[key])
        else:
            extracted_vals.extend(rule[key])
    extracted_vals_set = set(extracted_vals)

    # unique_subkeys { counts, { value, counts} }
    unique_subkeys = {}
    unknown_subkeys = {}
    for item in extracted_vals:
        subkey = find_str_in_list(item, known_subkeys)
        if subkey:
            # known subkey
            if type(item) is str:
                idx = item.find(subkey)
                if idx > -1:
                    the_value = item[idx+len(subkey):]
                else:
                    the_value = item
            else:
                the_value = str(item)
        else:
            # unknown subkey
            if type(item) is str:
                the_value = item
            else:
                the_value = str(item)

        if subkey:
            if subkey in unique_subkeys:
                unique_subkeys[subkey][0] += 1
                if the_value in unique_subkeys[subkey][1]:
                    unique_subkeys[subkey][1][the_value] += 1
                else:
                    unique_subkeys[subkey][1][the_value] = 1
            else:
                unique_subkeys[subkey] = [1, {the_value:1}]
        else:
            if the_value in unknown_subkeys:
                unknown_subkeys[the_value] += 1
            else:
                unknown_subkeys[the_value] = 1

    output = '{key} number={extracted_vals_num}<br>'.format(key=key, extracted_vals_num=len(extracted_vals_set))
    if b_detail:
        for key in sorted(unique_subkeys.keys()):
            output += '&nbsp;&nbsp;&nbsp;&nbsp;' + str(key) + ' | ' + str(unique_subkeys[key][0]) + ' | ' + format(unique_subkeys[key][0]/rulenum*100.0, '.1f') + '% | ' + str(len(unique_subkeys[key][1])) + '<br>'
            if not (key in ignored_strs):
                for value in sorted(unique_subkeys[key][1].keys()):
                    output += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' + str(value) + ' | ' + str(unique_subkeys[key][1][value]) + ' | ' + format(unique_subkeys[key][1][value]/rulenum*100.0, '.1f') + '%<br>'
        if len(unknown_subkeys.keys()) > 0:
            output += '&nbsp;&nbsp;&nbsp;&nbsp;unknown subkeys | ' + str(len(unknown_subkeys.keys())) + '<br>'
            for item in sorted(unknown_subkeys.keys()):
                output += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' + str(item) + ' | ' + str(unknown_subkeys[item]) + ' | ' + format(unknown_subkeys[item]/rulenum*100.0, '.1f') + '%<br>'
        output += '<br>'
    return output


def show_analyzed_rules(rules):
    output = show_analyzed_unique_value(rules, 'sid')
    output += show_analyzed_unique_value(rules, 'gid')
    output += show_analyzed_unique_value(rules, 'rev')
    output += show_analyzed_unique_value(rules, 'action')
    output += show_analyzed_unique_value(rules, 'classtype')
    output += show_analyzed_unique_value(rules, 'msg')
    output += show_analyzed_unique_value(rules, 'header')
    output += show_analyzed_unique_value(rules, 'metadata', True, ['created_at', 'updated_at', 'former_category', 'deployment', 'signature_severity', 'attack_target', 'affected_product', 'malware_family', 'performance_impact', 'tag', 'cve'],
                                                                  ['created_at', 'updated_at', 'former_category'])
    output += show_analyzed_unique_value(rules, 'options', True, ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', 'pcre:', 'classtype:', 'flow:', 'distance:', 'depth:', 'within:', 'flowbits:', 'threshold:', 'byte_test:', 'offset:', 'bsize:', 'isdataat:', 'dsize:', 'urilen:', 'fast_pattern:', 'byte_extract:', 'stream_size:', 'asn1:', 'byte_jump:', 'detection_filter:', 'dns.query;', 'dns_query;', 'dotprefix;', 'endswith;', 'fast_pattern;', 'file.data;', 'file_data;', 'flags:', 'ftpbounce;', 'icode:', 'itype:', 'ip_proto:', 'noalert;', 'ja3.hash;', 'ja3.string;', 'ja3_hash;', 'ja3s.hash;', 'http.accept;', 'http.accept_enc;', 'http.accept_lang;', 'http.connection;', 'http.content_len;', 'http.content_type;', 'http.cookie;', 'http.header.raw;', 'http.header_names;', 'http.header;', 'http.host.raw;', 'http.host;', 'http.location;', 'http.method;', 'http.protocol;', 'http.server;', 'http.start;', 'http.uri.raw;', 'http.referer;', 'http.request_body;', 'http.request_line;', 'http.response_body;', 'http.response_line;', 'http.stat_code;', 'http.stat_msg;', 'http.uri;', 'http.user_agent;', 'http_header_names;', 'http_uri;', 'http_user_agent;', 'rawbytes;', 'ssh_proto;', 'ssl_state:', 'ssl_version:', 'startswith;', 'tag:', 'tls.cert_issuer;', 'tls.cert_serial;', 'tls.cert_subject;', 'tls.sni;', 'ttl:', 'xbits:'],
                                                                 ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', 'pcre:'])
    return output

def analyze_list(the_list):
    value = []
    for item in the_list:
        value.append(str(item))
    return value

def analyze_ruleset(rule_file):
    from server.util.util_text_file import get_lines
    from suricataparser import parse_rule, parse_file
    s_ruleset_path = '/Users/huangstan/srv/data/' + 'rules/'

    ### read file in all_lines
    the_rules = []
    all_lines = get_lines(s_ruleset_path + rule_file)
    ### process all lines
    for line in all_lines:
        # if line[0] != '#':
        rule = parse_rule(line)
        if rule:
            if rule.enabled == True:
                the_rule = {}
                the_rule['sid'] = rule.sid
                the_rule['gid'] = rule._gid
                the_rule['rev'] = rule.rev
                the_rule['action'] = rule.action
                the_rule['classtype'] = rule.classtype
                the_rule['msg'] = rule.msg
                the_rule['header'] = rule.header
                the_rule['metadata'] = analyze_list(rule.metadata)
                the_rule['options'] = analyze_list(rule.options)
                the_rules.append(the_rule)
    return the_rules

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
    rules = analyze_ruleset(rule_file)
    return show_analyzed_rules(rules)

# suricata ruleset parser
@area51.route('/suricata-rulesets', methods=['GET'])
def suricata_rulesets():
    from server.util.util_file import get_name_list_of_files

    ### get file list
    s_ruleset_path = '/Users/huangstan/srv/data/' + 'rules/'
    rule_files = get_name_list_of_files(s_ruleset_path)

    ### read file in all_lines
    rules = []
    for rule_file in rule_files:
        rules.extend(analyze_ruleset(rule_file))
    return show_analyzed_rules(rules)
    