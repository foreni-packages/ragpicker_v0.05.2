# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import json
import logging
from core.abstracts import Report

try:
	from yapsy.IPlugin import IPlugin
except ImportError:
	raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

try:
	import utils.hpfeeds as hpfeeds
except ImportError:
	raise ImportError, 'Unable to import HPFeeds library: https://github.com/rep/hpfeeds'

log = logging.getLogger("ReportingHPFriends")

class HPFriends(IPlugin, Report):

	def run(self, results, objfile):
		host = self.options.get("host", "hpfriends.honeycloud.net")
		port = self.options.get("port", 20000)
		ident = self.options.get("ident")
		secret = self.options.get("secret")
		channel_reports = self.options.get("channel_reports")
		channel_files = self.options.get("channel_files")
		
		if not ident or not secret:
			raise Exception("HPFriends Identifier and Secret not configurated")
		
		try:
			#Connect to HPFriends
			hpc = hpfeeds.HPC(host, port, ident, secret, timeout=60)
			
			if channel_reports:
				#publish JSON-Report on the HPFriends channel
				log.info("publish JSON-Report on the HPFriends channel %s" % channel_reports)
				hpc.publish(channel_reports, json.dumps(results, default=self.date_handler, sort_keys=False, indent=4))
			
			if channel_files:
				#publish RAW-File as BASE64 on the HPFriends channel
				log.info("publish BASE64 on the HPFriends channel %s" % channel_files)
				hpc.publish(channel_files, json.dumps(objfile.get_fileB64encode(), sort_keys=False, indent=4))
		except hpfeeds.FeedException as e:
			raise Exception("publish on the channel failed: %s" % e)
		finally:
			hpc.close()