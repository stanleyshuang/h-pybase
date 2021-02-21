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
from server.util.util_suricata_rulesets import parse_ruleset, show_rules_value_analysis, output_risk_csv
from server.util.util_text_file import get_lines

s_static_data_path = '../static/'
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
@area51.route('/suricata-rulesets-csv', methods=['GET'])
def suricata_rulesets_csv():
    ### get file list
    rule_files = get_name_list_of_files(s_ruleset_path)
    ### read file in all_lines
    rules = []
    for rule_file in rule_files:
        all_lines = get_lines(s_ruleset_path + rule_file)
        rules.extend(parse_ruleset(all_lines))
    return output_risk_csv(rules)
