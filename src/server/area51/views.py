# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import json

from . import area51
from flask import jsonify

def check_key_unique_value(objs, key, b_detail=False, ignored_strs = [], counted_strs = []):
    objnum = len(objs)

    extracted = []
    for obj in objs:
        if type(obj[key]) is not list:
            extracted.append(obj[key])
        else:
            extracted.extend(obj[key])

    # count strings that are important
    keycounts = {}
    if counted_strs and len(counted_strs) > 0:
        for subs in counted_strs:
            for item in extracted:
                if subs in item:
                    if subs in keycounts:
                        keycounts[subs] += 1
                    else:
                        keycounts[subs] = 1

    # ignore strings that are not important
    if ignored_strs and len(ignored_strs) > 0:
        for subs in ignored_strs:
            extracted = [i for i in extracted if subs not in i]

    # unique strings
    extracted_dict = {}
    for item in extracted:
        if item in extracted_dict:
            extracted_dict[item] += 1
        else:
            extracted_dict[item] = 1
    extracted_num = len(extracted_dict)

    output = '{key} number={extracted_num}<br>'.format(key=key, extracted_num=extracted_num)
    if b_detail:
        for key in sorted(keycounts.keys()):
            output += '&nbsp;&nbsp;&nbsp;&nbsp;' + str(key) + ' | ' + str(keycounts[key]) + ' | ' + format(keycounts[key]/objnum*100.0, '.1f') + '%<br>'
        output += '<br>'
        for key in sorted(extracted_dict.keys()):
            output += '&nbsp;&nbsp;&nbsp;&nbsp;' + str(key) + ' | ' + str(extracted_dict[key]) + ' | ' + format(extracted_dict[key]/objnum*100.0, '.1f') + '%<br>'
    output += '<br>'
    return output


def dump_objs(objs):
    output = check_key_unique_value(objs, 'sid')
    output += check_key_unique_value(objs, 'gid')
    output += check_key_unique_value(objs, 'rev')
    output += check_key_unique_value(objs, 'action')
    output += check_key_unique_value(objs, 'classtype', True)
    output += check_key_unique_value(objs, 'msg')
    output += check_key_unique_value(objs, 'header')
    output += check_key_unique_value(objs, 'metadata', True, ['created_at', 'updated_at', 'former_category', 'deployment', 'signature_severity', 'attack_target', 'affected_product', 'malware_family', 'performance_impact', 'tag', 'cve'], 
                                                             ['created_at', 'updated_at', 'former_category', 'deployment', 'signature_severity', 'attack_target', 'affected_product', 'malware_family', 'performance_impact', 'tag', 'cve'])
    output += check_key_unique_value(objs, 'options', True, ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'classtype:', 'rev:', 'id:', 'nocase;', 'flow:', 'distance:', 'depth:', 'pcre:', 'within:', 'flowbits:', 'threshold:', 'byte_test:', 'offset:', 'bsize:', 'isdataat:', 'dsize:', 'urilen:', 'fast_pattern:', 'byte_extract:', 'stream_size:', 'asn1:', 'base64_data;', 'base64_decode:', 'byte_jump:', 'detection_filter:', 'dns.query;', 'dns_query;', 'dotprefix;', 'endswith;', 'fast_pattern;', 'file.data;', 'file_data;', 'flags:', 'ftpbounce;', 'icode:', 'itype:', 'ip_proto:', 'noalert;', 'ja3.hash;', 'ja3.string;', 'ja3_hash;', 'ja3s.hash;', 'http.accept;', 'http.accept_enc;', 'http.accept_lang;', 'http.connection;', 'http.content_len;', 'http.content_type;', 'http.cookie;', 'http.header.raw;', 'http.header_names;', 'http.header;', 'http.host.raw;', 'http.host;', 'http.location;', 'http.method;', 'http.protocol;', 'http.server;', 'http.start;', 'http.uri.raw;', 'http.referer;', 'http.request_body;', 'http.request_line;', 'http.response_body;', 'http.response_line;', 'http.stat_code;', 'http.stat_msg;', 'http.uri;', 'http.user_agent;', 'http_header_names;', 'http_uri;', 'http_user_agent;', 'rawbytes;', 'ssh_proto;', 'ssl_state:', 'ssl_version:', 'startswith;', 'tag:', 'tls.cert_issuer;', 'tls.cert_serial;', 'tls.cert_subject;', 'tls.sni;', 'ttl:', 'xbits:'],
                                                            ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'classtype:', 'rev:', 'id:', 'nocase;', 'flow:', 'distance:', 'depth:', 'pcre:', 'within:', 'flowbits:', 'threshold:', 'byte_test:', 'offset:', 'bsize:', 'isdataat:', 'dsize:', 'urilen:', 'fast_pattern:', 'byte_extract:', 'stream_size:', 'asn1:', 'base64_data;', 'base64_decode:', 'byte_jump:', 'detection_filter:', 'dns.query;', 'dns_query;', 'dotprefix;', 'endswith;', 'fast_pattern;', 'file.data;', 'file_data;', 'flags:', 'ftpbounce;', 'icode:', 'itype:', 'ip_proto:', 'noalert;', 'ja3.hash;', 'ja3.string;', 'ja3_hash;', 'ja3s.hash;', 'http.accept;', 'http.accept_enc;', 'http.accept_lang;', 'http.connection;', 'http.content_len;', 'http.content_type;', 'http.cookie;', 'http.header.raw;', 'http.header_names;', 'http.header;', 'http.host.raw;', 'http.host;', 'http.location;', 'http.method;', 'http.protocol;', 'http.server;', 'http.start;', 'http.uri.raw;', 'http.referer;', 'http.request_body;', 'http.request_line;', 'http.response_body;', 'http.response_line;', 'http.stat_code;', 'http.stat_msg;', 'http.uri;', 'http.user_agent;', 'http_header_names;', 'http_uri;', 'http_user_agent;', 'rawbytes;', 'ssh_proto;', 'ssl_state:', 'ssl_version:', 'startswith;', 'tag:', 'tls.cert_issuer;', 'tls.cert_serial;', 'tls.cert_subject;', 'tls.sni;', 'ttl:', 'xbits:'])
    '''
    for obj in objs:
        # output += json.dumps(obj) + '<br>'
        output += 'header: ' + obj['header'] + '<br>'
        output += 'metadata: ' + dump_list(obj['metadata']) + '<br>'
        output += 'options: ' + dump_list(obj['options']) + '<br>'
    '''
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
    