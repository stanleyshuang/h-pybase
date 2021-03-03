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

def output_value_of_subkey(rule_data, subkey):
    indices = [i for i, value in enumerate(rule_data) if subkey in value]
    if len(indices) > 0:
        output_value = ''
        for i, idx in enumerate(indices):
            if i > 0:
                output_value += ', '
            output_value += rule_data[idx] 
    else:
        output_value = 'n/a'
    return output_value, indices

def output_count_of_subkey(rule_data, subkey):
    indices = [i for i, value in enumerate(rule_data) if subkey in value]
    return len(indices)

# parse sample: 'reference:cve,2001-1021;'
#               'reference:cve,CVE-2010-3973;'
#               'reference:cve,CVE_2012-5958;'
#               'reference:cve,2018???16130;'
def cve_score(value):
    if value.find('reference:cve,') == -1:
        return 0
    start = value.find('cve,') + len('cve,')
    if value.lower().startswith(('cve-', 'can-'), start):
        start = value.find('-') + len('-')
    elif value.lower().startswith(('cve_', 'can_'), start):
        start = value.find('_') + len('_')
    end = value.find('-', start)
    substring = value[start:end]

    if type(substring) is int or substring.isnumeric():
        year = int(substring)
        if year > 2010:
            return year - 2010
        else:
            return 1
    else:
        if substring == '2018???16130':
            return 8
        else:
            print('cve could not be parsed: ' + substring)
            return 1


def output_risk_tsv(rules, mode='released'):
    from datetime import datetime
    now = datetime.now()
    dt_string = now.strftime("%Y%m%d-%H%M%S")
    lines = ['# build:' + dt_string + '\n']

    # 2021-02-22    80都是malware, exploit 跟shellcode
    #               classtype:misc-activity 也是扣10吧
    #               classtype:trojan-activity 這比較可信
    #               signature_severity Major ,但 classtype:misc-activity 是misc-activity 應該就是20
    #               但若是trojan-activity 是40分, 但有malware_family 你就可以加分,且malware_family ,若有reference應該可信度又更高
    #               基本former_category USER_AGEAGT 去判斷很容易務斷,雖然很多bot 會用自己的，但行為不一定都是有問題
    # 2021-02-23    content 愈多 比較這個rule 比較不會FP
    
    if mode == 'labelled':
        s_labelled_sids = {    
                    2024897: 20, # 
                    2102496: 60, # 2021-02-23    20分裡,有些有CVE 且有MS的patch的, 分數應該要60比較好, reference:cve,2003-0813;, reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx;
                    2102491: 60, #               reference:cve,2003-0813;, reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx;
                    2102385: 60, #               reference:cve,2003-0818;
                    2027189: 40, #               這個20分就不太合理說
                    2025728: 60, # 2021-02-24    70分以上,但IOS可以放在例外，ET MOBILE_MALWARE iOS/Bahamut DNS Lookup 2
                    2024672: 80, #               ET EXPLOIT Apache Struts 2 REST Plugin (B64) 5 比 MOBILE_MALWARE 嚴重
                    2101919: 80, # 2021-02-25    GPL FTP CWD overflow attempt: cve 2004 以前
                    2101734: 80, #               GPL FTP USER overflow attempt: cve 2004 以前
                    2008690: 85, #               ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (1)，MS08-067 是很有名的漏洞
                    2009610: 70, #               
                    2012143: 75, #
                    2012153: 76, #
                    2101972: 50, #               reference:cve,2000-1035; 太舊了
        }
    else:
        s_labelled_sids = {}

    s_high_risk_classtype = {
                    'attempted-user': 'Attempted User Privilege Gain',
                    'unsuccessful-user': 'Unsuccessful User Privilege Gain',
                    'successful-user': 'Successful User Privilege Gain',
                    'attempted-admin': 'Attempted Administrator Privilege Gain',
                    'successful-admin': 'Successful Administrator Privilege Gain',
                    'shellcode-detect': 'Executable code was detected',
                    'trojan-activity': 'A Network Trojan was detected',
                    'web-application-attack': 'Web Application Attack',
                    'kickass-porn': 'SCORE! Get the lotion!',
                    'policy-violation': 'Potential Corporate Privacy Violation',
                    'targeted-activity': 'Targeted Malicious Activity was Detected',
                    'exploit-kit': 'Exploit Kit Activity Detected',
                    'domain-c2': 'Domain Observed Used for C2 Detected',
                    'credential-theft': 'Successful Credential Theft Detected',
                    'command-and-control': 'Malware Command and Control Activity Detected'
    }

    s_mid_risk_classtype = {
                    'bad-unknown': 'Potentially Bad Traffic',
                    'attempted-recon': 'Attempted Information Leak',
                    'successful-recon-limited': 'Information Leak',
                    'successful-recon-largescale': 'Large Scale Information Leak',
                    'attempted-dos': 'Attempted Denial of Service',
                    'successful-dos': 'Denial of Service',
                    'rpc-portmap-decode': 'Decode of an RPC Query',
                    'suspicious-filename-detect': 'A suspicious filename was detected',
                    'suspicious-login': 'An attempted login using a suspicious username was detected',
                    'system-call-detect': 'A system call was detected',
                    'unusual-client-port-connection': 'A client was using an unusual port',
                    'denial-of-service': 'Detection of a Denial of Service Attack',
                    'non-standard-protocol': 'Detection of a non-standard protocol or event',
                    'web-application-activity': 'access to a potentially vulnerable web application',
                    'misc-attack': 'Misc Attack',
                    'default-login-attempt': 'Attempt to login by a default username and password',
                    'external-ip-check': 'Device Retrieving External IP Address Detected',
                    'pup-activity': 'Possibly Unwanted Program Detected',
                    'social-engineering': 'Possible Social Engineering Attempted',
                    'coin-mining': 'Crypto Currency Mining Activity Detected'
    }

    s_low_risk_classtype = {
                    'not-suspicious': 'Not Suspicious Traffic',
                    'unknown': 'Unknown Traffic',
                    'string-detect': 'A suspicious string was detected',
                    'network-scan': 'Detection of a Network Scan',
                    'protocol-command-decode': 'Generic Protocol Command Decode',
                    'misc-activity': 'Misc activity',
                    'icmp-event': 'Generic ICMP event'
    }

    s_info_risk_classtype = {
                    'tcp-connection': 'A TCP connection was detected'
    }

    rulenum = len(rules)

    if mode == 'verbose' or mode == 'labelled':
        lines.append('sid\tscore\tmsg\tclasstype\tsignature_severity\tmalware_family\tformer_category\tcontent counts\treference counts\treference\n')
    else:
        lines.append('sid\tscore\tmsg\n')
    # extract values into extracted_vals and extracted_vals_set
    for rule in rules:
        signature_severity, signature_severity_indices = output_value_of_subkey(rule['metadata'], 'signature_severity')
        malware_family, malware_family_indices = output_value_of_subkey(rule['metadata'], 'malware_family')
        former_category, former_category_indices = output_value_of_subkey(rule['metadata'], 'former_category')
        content_count = output_count_of_subkey(rule['options'], 'content')
        reference_count = output_count_of_subkey(rule['options'], 'reference')
        reference, reference_indices = output_value_of_subkey(rule['options'], 'reference')

        score = 0
        if rule['sid'] in s_labelled_sids:
            score = s_labelled_sids[rule['sid']]
        else:
            # classtype
            if 'classtype' in rule and rule['classtype'] in s_info_risk_classtype:
                score = 5
            elif 'classtype' in rule and rule['classtype'] in s_low_risk_classtype:
                score = 15
            elif 'classtype' in rule and rule['classtype'] in s_mid_risk_classtype:
                score = 25
            elif 'classtype' in rule and rule['classtype'] in s_high_risk_classtype:
                score = 35
            else:
                score = 20

            # signature_severity
            for i in signature_severity_indices:
                if 'Critical' in rule['metadata'][i]:
                    score += 40
                elif 'Major' in rule['metadata'][i]:
                    score += 20
                elif 'Minor' in rule['metadata'][i]:
                    score += 5

            # malware_family
            for i in malware_family_indices:
                score += 5

            # reference
            if len(reference_indices) < 10:
                score += len(reference_indices)
            else:
                score += 10

            b_mspx = False
            b_cve = False
            for i in reference_indices:
                if not b_mspx and '.mspx' in rule['options'][i]:
                    score += 10
                    b_mspx = True
                elif not b_cve and 'cve' in rule['options'][i]:
                    score += cve_score(rule['options'][i])
                    b_cve = True
                else:
                    pass

            # content
            if content_count > 10:
                score += 5
            else:
                score += int(content_count/2)

            # msg
            if ' iOS' in rule['msg']:
                score -= 15
            elif 'Android' in rule['msg']:
                score -= 15
            elif 'MS08-067' in rule['msg']:
                score += 30
            else:
                pass

            # score
            if score > 100:
                score = 100

            if score < 0:
                score = 0

        print('--->')
        print(rule['msg'])
        print(rule['classtype'] if 'classtype' in rule and rule['classtype'] else 'n/a')
        print(signature_severity)
        print(malware_family)
        print(former_category) 
        print(str(content_count)) 
        print(str(reference_count)) 
        print(reference)

        if mode == 'verbose' or mode == 'labelled':
            lines.append(str(rule['sid']) + '\t' + str(score) + '\t' + (rule['msg'] if 'msg' in rule else 'n/a') +
                        '\t' + rule['classtype'] if 'classtype' in rule and rule['classtype'] else 'n/a' +
                        '\t' + signature_severity +
                        '\t' + malware_family + 
                        '\t' + former_category +
                        '\t' + str(content_count) + 
                        '\t' + str(reference_count) + 
                        '\t' + reference +
                        '\n')
        else:
            lines.append(str(rule['sid']) + '\t' + str(score) + '\t' + (rule['msg'] if rule['msg'] else 'n/a') + '\n')
    return lines
