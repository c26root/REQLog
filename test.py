#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import DOMAIN, ADMIN_DOMAIN, DOMAIN_COUNT

request_host = '6hkn0yr3.log.app'

if request_host != ADMIN_DOMAIN and request_host.endswith('.' + DOMAIN):
    if request_host.count('.') >= DOMAIN_COUNT:
        domain = '.'.join(request_host.split('.')[-(DOMAIN_COUNT+2):])
        query = 'SELECT * FROM user where domain = ?'
        print query, domain.replace('.' + DOMAIN, '')