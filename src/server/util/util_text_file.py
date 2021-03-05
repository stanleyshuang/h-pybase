#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  helloworld 1.0
# Date:     2020-12-04
# 

def get_lines(filename, encoding='utf-8'):
    with open(filename, 'r', encoding=encoding) as fp:
        all_lines = fp.readlines()
        return all_lines
    return None

def write_lines(filename, all_lines):
    with open(filename, 'w') as fp:
    	fp.writelines(all_lines)

def write_output(filename, output):
    with open(filename, 'w') as fp:
    	fp.writeline(output)
