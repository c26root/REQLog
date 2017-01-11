#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
from dnslib.server import DNSServer, DNSHandler, DNSRecord

q = DNSRecord.question("test.me")
a = q.send("localhost", 53)
print DNSRecord.parse(a)
