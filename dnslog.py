#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
import sqlite3
from config import DOMAIN, DOMAIN_COUNT, NAMESERVER_IP, SERVER_IP, DATABASE
from dnslib import RR, QTYPE
from dnslib.server import DNSServer, DNSHandler, DNSRecord


class DomainResolver():

    def resolve(self, request, handler):

        reply = request.reply()
        qname = request.q.qname.__str__()
        qtype = request.q.qtype

        if unsafedomain(qname):
            print 'unsafedomain', qname
            reply.add_answer(*RR.fromZone("{0}. 60 A 8.8.8.8".format(qname)))
            return reply

        if not is_subdomain(qname):
            reply.add_answer(*RR.fromZone("{0}. 60 A 8.8.8.8".format(qname)))
            return reply

        domain = get_domain(qname)

        if domain:
            domain_hash = domain.replace('.' + DOMAIN, '')

        if not is_valid_domain(domain_hash):
            reply.add_answer(*RR.fromZone("{0}. 60 A 8.8.8.8".format(qname)))
            return reply

        # 合法存在的域名
        reply.add_answer(
            *RR.fromZone("{0}. 60 A {1}".format(qname, SERVER_IP)))

        date = time.strftime("%Y-%M-%d %X")
        client_ip, client_port = handler.client_address

        # 入库
        query = "INSERT INTO dns (qname, domain, qtype, client_ip, date) VALUES (?, ?, ?, ?, ?);"
        result = query_db(query, args=(
            qname, domain, QTYPE[qtype], client_ip, date))
        db.commit()

        print qname, domain, QTYPE[qtype], date

        return reply

# 简单检查合法域名
def unsafedomain(s):
    return '<' in s or '>' in s

# 是否子域名
def is_subdomain(qname):
    if qname.rstrip('.').endswith(DOMAIN):
        return True
    return False

# 获取子域名
def get_domain(qname):
    qname = qname.rstrip('.')
    if qname.count('.') >= DOMAIN_COUNT:
        domain = '.'.join(qname.split('.')[-(DOMAIN_COUNT+2):])
        return domain
    return False

# 检查是否存在的子域名
def is_valid_domain(domain):
    global db
    query = 'SELECT * FROM user where domain = ?'
    result = query_db(query, args=(domain, ))
    if not len(result):
        return False
    return True

# 建立连接
def connect_db():
    return sqlite3.connect(DATABASE, check_same_thread=False)


# 辅助查询 字段
def query_db(query, args=(), one=False):
    global db
    cur = db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


if __name__ == '__main__':
    db = connect_db()
    # 启动服务
    resolver = DomainResolver()
    server = DNSServer(resolver, port=53, address='localhost')
    server.start()
