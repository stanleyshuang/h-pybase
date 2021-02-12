# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#

from . import area51
from flask import jsonify

@area51.after_app_request
def after_request(response):
    return response

# sanity check route
@area51.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify('pong!')

# test utility
@area51.route('/suricata-rulesets/<string:input_file>', methods=['GET'])
def util_test(input_file):
    from server.util.util_text_file import get_lines
    from suricataparser import parse_rule, parse_file 
    ### read file in all_lines
    all_lines = get_lines('/Users/huangstan/srv/data/' + input_file)
    output = ''
    ### process all lines
    for line in all_lines:
        if line[0] != '#':
            rule = parse_rule(line)
            if rule:
                if rule.enabled == True:
                    output += 'action={action}, classtype={classtype}, header={header}, metadata={metadata}, msg={msg}, options={options}, rev={rev}, sid={sid}, gid={gid}<br>'.format(
                                            action = rule.action,
                                            classtype = rule.classtype,
                                            header = str(rule.header),
                                            metadata = str(rule.metadata),
                                            msg = rule.msg,
                                            options = str(rule.options),
                                            rev = rule.rev,
                                            sid = rule.sid,
                                            gid = rule._gid)
                else:
                    output += 'xxxxxxxx<br>'
    return output
