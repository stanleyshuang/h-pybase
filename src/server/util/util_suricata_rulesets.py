# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  Duffy ver. 2.0
# Date:     2017/12/15
# 
from suricataparser import parse_rule, parse_file


def find_str_in_list(the_str, the_list):
    for subs in the_list:
        if subs in the_str:
            return subs
    return None

def show_unique_value(rules, key, b_detail=False, known_subkeys = [], ignored_strs = []):
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

def show_rules_value_analysis(rules):
    output = show_unique_value(rules, 'sid')
    output += show_unique_value(rules, 'gid')
    output += show_unique_value(rules, 'rev')
    output += show_unique_value(rules, 'action')
    output += show_unique_value(rules, 'classtype')
    output += show_unique_value(rules, 'msg')
    output += show_unique_value(rules, 'header')
    output += show_unique_value(rules, 'metadata', True, ['created_at', 'updated_at', 'former_category', 'deployment', 'signature_severity', 'attack_target', 'affected_product', 'malware_family', 'performance_impact', 'tag', 'cve'],
                                                         ['created_at', 'updated_at', 'former_category'])
    output += show_unique_value(rules, 'options', True, ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', 'pcre:', 'classtype:', 'flow:', 'distance:', 'depth:', 'within:', 'flowbits:', 'threshold:', 'byte_test:', 'offset:', 'bsize:', 'isdataat:', 'dsize:', 'urilen:', 'fast_pattern:', 'byte_extract:', 'stream_size:', 'asn1:', 'byte_jump:', 'detection_filter:', 'dns.query;', 'dns_query;', 'dotprefix;', 'endswith;', 'fast_pattern;', 'file.data;', 'file_data;', 'flags:', 'ftpbounce;', 'icode:', 'itype:', 'ip_proto:', 'noalert;', 'ja3.hash;', 'ja3.string;', 'ja3_hash;', 'ja3s.hash;', 'http.accept;', 'http.accept_enc;', 'http.accept_lang;', 'http.connection;', 'http.content_len;', 'http.content_type;', 'http.cookie;', 'http.header.raw;', 'http.header_names;', 'http.header;', 'http.host.raw;', 'http.host;', 'http.location;', 'http.method;', 'http.protocol;', 'http.server;', 'http.start;', 'http.uri.raw;', 'http.referer;', 'http.request_body;', 'http.request_line;', 'http.response_body;', 'http.response_line;', 'http.stat_code;', 'http.stat_msg;', 'http.uri;', 'http.user_agent;', 'http_header_names;', 'http_uri;', 'http_user_agent;', 'rawbytes;', 'ssh_proto;', 'ssl_state:', 'ssl_version:', 'startswith;', 'tag:', 'tls.cert_issuer;', 'tls.cert_serial;', 'tls.cert_subject;', 'tls.sni;', 'ttl:', 'xbits:'],
                                                        ['sid:', 'metadata:', 'msg:', 'content:', 'reference:', 'rev:', 'id:', 'nocase;', 'pcre:'])
    return output

def parse_list_value(the_list):
    value = []
    for item in the_list:
        value.append(str(item))
    return value

def parse_a_rule(line):
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
            the_rule['metadata'] = parse_list_value(rule.metadata)
            the_rule['options'] = parse_list_value(rule.options)
            return the_rule
    return None

def parse_ruleset(all_lines):
    the_rules = []
    for line in all_lines:
        a_rule = parse_a_rule(line)
        if a_rule:
            the_rules.append(a_rule)
    return the_rules

def output_risk_tsv(rules):
    s_low_risk_sids = [] # [2024897]
    s_low_risk_classtype = ['misc-activity']
    s_high_risk_classtype = [
                            'attempted-user',
                            'unsuccessful-user',
                            'successful-user',
                            'attempted-admin',
                            'successful-admin',
                            'shellcode-detect',
                            'trojan-activity',
                            'web-application-attack',
                            'kickass-porn',
                            'policy-violation',
                            'targeted-activity',
                            'exploit-kit',
                            'domain-c2',
                            'credential-theft',
                            'command-and-control']
    rulenum = len(rules)

    lines = ['sid\tscore\tmsg\n']
    # extract values into extracted_vals and extracted_vals_set
    for rule in rules:
        score = 20
        if rule['sid'] in s_low_risk_sids:
            score = 20
        else:
            if 'classtype' in rule and rule['classtype'] in s_low_risk_classtype:
                score = 20
            elif 'classtype' in rule and rule['classtype'] in s_high_risk_classtype:
                score = 40
                indices = [i for i, value in enumerate(rule['metadata']) if 'signature_severity' in value]
                for i in indices:
                    if 'Critical' in rule['metadata'][i]:
                        score += 40
                    elif 'Major' in rule['metadata'][i]:
                        score += 20
                indices = [i for i, value in enumerate(rule['options']) if 'malware_family' in value]
                for i in indices:
                    score += 1
        lines.append(str(rule['sid']) + '\t' + str(score) + '\t' + (rule['msg'] if rule['msg'] else 'n/a') + '\n')
    return lines
