#!/usr/bin/python3

import sys, os
CUR_DIR = os.path.realpath(os.path.dirname(__file__))
print(CUR_DIR)
sys.path.append(CUR_DIR)

import binwalk

with binwalk.Modules(*(['-q', '-f', 'log'] + sys.argv[1:]), signature=True) as mod:
    print(mod.execute())
