# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import json

from . import area51
from flask import jsonify

def analyze_key_unique_value(objs, key, b_detail=False, ignored_strs = [], counted_strs = []):
    objnum = len(objs)

    extracted = []
    for obj in objs:
        if type(obj[key]) is not list:
            extracted.append(obj[key])
        else:
            extracted.extend(obj[key])

    extracted_set = set(extracted)

    # count keys that are important
    keycounts = {}
    for subs in counted_strs:
        for item in extracted:
            if subs in item:
                if subs in keycounts:
                    keycounts[subs][0] += 1
                    idx = item.find(':')
                    if idx > -1:
                        # insert item[idx+1:] into keycounts[subs][1]
                        if str(item[idx+1:]) in keycounts[subs][1]:
                            keycounts[subs][1][str(item[idx+1:])] += 1
                        else:
                            keycounts[subs][1][str(item[idx+1:])] = 1
                    else:
                        # insert item into keycounts[subs][1]
                        if str(item) in keycounts[subs][1]:
                            keycounts[subs][1][str(item)] += 1
                        else:
                            keycounts[subs][1][str(item)] = 1
                else:
                    init_dict = {}
                    idx = item.find(':')
                    if idx > -1:
                        init_dict[str(item[idx+1:])] = 1
                    else:
                        init_dict[str(item)] = 1
                    keycounts[subs] = [1, init_dict]

    output = '{key} number={extracted_num}<br>'.format(key=key, extracted_num=len(extracted_set))
    if b_detail:
        for key in sorted(keycounts.keys()):
            output += '&nbsp;&nbsp;&nbsp;&nbsp;' + str(key) + ' | ' + str(keycounts[key][0]) + ' | ' + format(keycounts[key][0]/objnum*100.0, '.1f') + '% | ' + str(len(keycounts[key][1])) + '<br>'
            if not (key in ignored_strs):
                for value in sorted(keycounts[key][1].keys()):
                    output += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' + str(value) + ' | ' + str(keycounts[key][1][value]) + ' | ' + format(keycounts[key][1][value]/objnum*100.0, '.1f') + '%<br>'
        output += '<br>'
    return output


def dump_objs(objs):
    output = analyze_key_unique_value(objs, 'sid')
    output += analyze_key_unique_value(objs, 'gid')
    output += analyze_key_unique_value(objs, 'rev')
    output += analyze_key_unique_value(objs, 'action')
    output += analyze_key_unique_value(objs, 'classtype')
    output += analyze_key_unique_value(objs, 'msg')
    output += analyze_key_unique_value(objs, 'header')
    output += analyze_key_unique_value(objs, 'metadata', True, ['created_at', 'updated_at', 'former_category'], 
                                                             ['created_at', 'updated_at', 'former_category', 'deployment', 'signature_severity', 'attack_target', 'affected_product', 'malware_family', 'performance_impact', 'tag', 'cve'])
    output += analyze_key_unique_value(objs, 'options', True, ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', ],
                                                            ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', 'classtype:', 'flow:', 'distance:', 'depth:', 'pcre:', 'within:', 'flowbits:', 'threshold:', 'byte_test:', 'offset:', 'bsize:', 'isdataat:', 'dsize:', 'urilen:', 'fast_pattern:', 'byte_extract:', 'stream_size:', 'asn1:', 'base64_data;', 'base64_decode:', 'byte_jump:', 'detection_filter:', 'dns.query;', 'dns_query;', 'dotprefix;', 'endswith;', 'fast_pattern;', 'file.data;', 'file_data;', 'flags:', 'ftpbounce;', 'icode:', 'itype:', 'ip_proto:', 'noalert;', 'ja3.hash;', 'ja3.string;', 'ja3_hash;', 'ja3s.hash;', 'http.accept;', 'http.accept_enc;', 'http.accept_lang;', 'http.connection;', 'http.content_len;', 'http.content_type;', 'http.cookie;', 'http.header.raw;', 'http.header_names;', 'http.header;', 'http.host.raw;', 'http.host;', 'http.location;', 'http.method;', 'http.protocol;', 'http.server;', 'http.start;', 'http.uri.raw;', 'http.referer;', 'http.request_body;', 'http.request_line;', 'http.response_body;', 'http.response_line;', 'http.stat_code;', 'http.stat_msg;', 'http.uri;', 'http.user_agent;', 'http_header_names;', 'http_uri;', 'http_user_agent;', 'rawbytes;', 'ssh_proto;', 'ssl_state:', 'ssl_version:', 'startswith;', 'tag:', 'tls.cert_issuer;', 'tls.cert_serial;', 'tls.cert_subject;', 'tls.sni;', 'ttl:', 'xbits:'])
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

def parse_list(the_list):
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
                obj['metadata'] = parse_list(rule.metadata)
                obj['options'] = parse_list(rule.options)
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
    