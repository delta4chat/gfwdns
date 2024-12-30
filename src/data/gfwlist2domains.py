#!/bin/env python3

import sys
import os
import ipaddress

try:
    import abp
except ModuleNotFoundError:
    os.system('pip3 install python-abp')

from abp.filters import parse_filterlist

seen = set()

prefix = '|@/-!.*\\'
scheme = ('http://', 'https://', 'http:', 'https:', '\\')
ignore = '|@/-!*?#:"[\\'

for f in parse_filterlist(sys.stdin.read().split('\n')):
    if hasattr(f, 'selector') and hasattr(f, 'action'):
        v = f.selector.get('value')
        if v is None:
            continue

        if '.' not in v:
            continue

        for p in prefix:
            while v.startswith(p):
                v = v[1:]

        for s in scheme:
            while s in v:
                v = v.replace(s, '')

        if '/' in v:
            v = v.split('/')[0]

        if f.action != 'block':
            continue

        skip = False
        for i in ignore:
            if i in v:
                skip = True
                break

        if skip:
            continue

        try:
            ipaddress.ip_address(v)
        except:
            pass
        else:
            continue

        if v not in seen:
            seen.add(v)
            print('"', v, '",', sep='')
