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
from server.util.util_suricata_rulesets import parse_a_rule, parse_ruleset, show_rules_value_analysis, output_risk_tsv
from server.util.util_text_file import get_lines, write_lines

s_static_data_path = './static/'
s_output_data_path = './downloads/'
s_ruleset_path = s_static_data_path + 'rules/'


@area51.after_app_request
def after_request(response):
    return response

# sanity check route
@area51.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify('pong!')

# suricata ruleset parser
@area51.route('/suricata-ruleset-analyze-value/<string:rule_file>', methods=['GET'])
def suricata_ruleset_analyze_value(rule_file):
    all_lines = get_lines(s_ruleset_path + rule_file)
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
        all_lines = get_lines(s_ruleset_path + rule_file)
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
        all_lines = get_lines(s_ruleset_path + rule_file)
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
