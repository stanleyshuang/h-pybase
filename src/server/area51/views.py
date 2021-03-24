# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import json

from . import area51
from flask import jsonify

from server.util.util_file import get_name_list_of_files
from server.util.util_suricata_rulesets import parse_a_rule, parse_ruleset, show_rules_value_analysis, output_risk_tsv, test_match_sid
from server.util.util_text_file import get_lines, write_lines

s_encoding = 'utf-8' # 'windows-1252'
s_static_data_path = './static/'
s_output_data_path = './downloads/'
s_ruleset_path = s_static_data_path + 'rules/'


@area51.after_app_request
def after_request(response):
    return response

# sanity check route
@area51.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify('PONG!!')

# suricata ruleset parser
@area51.route('/suricata-ruleset-analyze-value/<string:rule_file>', methods=['GET'])
def suricata_ruleset_analyze_value(rule_file):
    all_lines = get_lines(s_ruleset_path + rule_file, s_encoding)
    rules = parse_ruleset(all_lines)
    return show_rules_value_analysis(rules)

# suricata ruleset parser
@area51.route('/suricata-rulesets-analyze-value', methods=['GET'])
def suricata_rulesets_analyze_value():
    ### get file list
    rule_files = get_name_list_of_files(s_ruleset_path)
    ### read file in all_lines
    rules = []
    for rule_file in rule_files:
        all_lines = get_lines(s_ruleset_path + rule_file, s_encoding)
        rules.extend(parse_ruleset(all_lines))
    return show_rules_value_analysis(rules)

# suricata ruleset parser
@area51.route('/suricata-rulesets-tsv/<string:mode>', methods=['GET'])
def suricata_rulesets_tsv(mode='released'):
    ### get file list
    rule_files = get_name_list_of_files(s_ruleset_path)
    ### read file in all_lines
    rules = []
    for rule_file in rule_files:
        all_lines = get_lines(s_ruleset_path + rule_file, s_encoding)
        rules.extend(parse_ruleset(all_lines))
    tsv_lines = output_risk_tsv(rules, mode)
    if mode == 'verbose':
        file_name = s_output_data_path + 'suricata_rulesets_analysis.tsv'
    elif mode == 'labelled':
        file_name = s_output_data_path + 'suricata_rulesets_analysis.tsv'
    else:
        file_name = s_output_data_path + 'suricata_rulesets_risk.tsv'
    write_lines(file_name, tsv_lines)
    output = ''
    for line in tsv_lines:
        output += line + '<br>'
    return output

# suricata ruleset parser
@area51.route('/suricata-ruleset-rule-review/<int:sid>', methods=['GET'])
def suricata_ruleset_rule_review(sid):
    ### get file list
    rule_files = get_name_list_of_files(s_ruleset_path)
    ### read file in all_lines
    output = ''
    for rule_file in rule_files:
        all_lines = get_lines(s_ruleset_path + rule_file)
        for line in all_lines:
            a_rule = parse_a_rule(line)
            if a_rule and type(a_rule['sid']) is int and a_rule['sid'] == sid:
                output += line + '<br>\n'
                write_lines(s_output_data_path + 'etopen_sid_{sid}.txt'.format(sid=str(sid)), line)
    return output

# test
@area51.route('/suricata-rulesets-sid-match', methods=['GET'])
def suricata_rulesets_sid_match():
    ### get file list
    rule_files = get_name_list_of_files(s_ruleset_path)
    ### read file in all_lines
    output = ""
    for rule_file in rule_files:
        all_lines = get_lines(s_ruleset_path + rule_file, s_encoding)
        b_matched, not_matched_counts, comment_count, sids = test_match_sid(all_lines)
        if not b_matched:
            count_result = '{count} sid not in parsed rules. '.format(count=str(count))
            comment_result = '{comment_count} lines are commented<br>\n'.format(comment_count=str(comment_count))
            output += '[' + rule_file + '] - ' + count_result + comment_result
        else:
            output += '[' + rule_file + '] - pass<br>\n'
    return output
