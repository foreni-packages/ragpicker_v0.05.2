#!/usr/bin/python
#                              _        _                
#   _ __   __ _   __ _  _ __  (_)  ___ | | __  ___  _ __ 
#  | '__| / _` | / _` || '_ \ | | / __|| |/ / / _ \| '__|
#  | |   | (_| || (_| || |_) || || (__ |   < |  __/| |   
#  |_|    \__,_| \__, || .__/ |_| \___||_|\_\ \___||_|   
#                |___/ |_|                               
#
# Plugin based malware crawler. 
# Use this tool if you are testing antivirus products, collecting malware 
# for another analyzer/zoo.
# Many thanks to the cuckoo-sandbox team for the Architectural design ideas.
# Includes code from cuckoo-sandbox (c) 2013 http://www.cuckoosandbox.org 
# and mwcrawler, (c) 2012 Ricardo Dias
#
# http://code.google.com/p/malware-crawler/
#
# Robby Zeitfuchs - robby@zeitfuchs.org - 2013-2014
#
# any subjection, tips, improvement are welcome
#
# Licence: GNU GPL v.3.0
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import logging
import time
import argparse
import Queue
import os
import socket
import utils.socks as socks
from core.worker import Worker
from utils.logo import logo 
from core.config import Config
from core.constants import RAGPICKER_ROOT
from core.constants import RAGPICKER_VERSION
from core.constants import RAGPICKER_BUILD_DATE

try:
	from yapsy.PluginManager import PluginManager
except ImportError:
	raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("Main")

def runCrawler():
	mapURL = {}
	cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf'))
	
	#TOR Socks proxy
	isTorEnabled = cfgCrawler.get("clientConfig").get("tor_enabled", False)
	
	if isTorEnabled:
		torProxyAdress = cfgCrawler.get("clientConfig").get("tor_proxyadress", "localhost")
		torProxyPort = cfgCrawler.get("clientConfig").get("tor_proxyport", 9050)
		# Route an HTTP request through the SOCKS proxy 
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, torProxyAdress, torProxyPort)
		socket.socket = socks.socksocket			
	
	# Build the PluginManager
	crawlerPluginManager = PluginManager()
	crawlerPluginManager.setPluginPlaces(["crawler"])
	crawlerPluginManager.collectPlugins()
	
	# Trigger run from the "Crawler" plugins
	for pluginInfo in crawlerPluginManager.getAllPlugins():
		crawlerModul = pluginInfo.plugin_object
		
		#Config for crawler module
		try:
			options = cfgCrawler.get(pluginInfo.name)
			crawlerModul.set_options(options)
		except Exception:
			log.error("Crawler module %s not found in configuration file", pluginInfo.name)  
			
		# If the crawler module is disabled in the config, skip it.
		if not options.enabled:
			continue
		
		log.info("Run Crawler: " + pluginInfo.name)
		
		try:
			returnMap = crawlerModul.run()
			mapURL.update(returnMap)
		except Exception as e:
			log.error('Error (%s) in %s', e, pluginInfo.name)
			
	return mapURL

def runWorker(mapURL, threads):
	queue = Queue.Queue()

	# create a thread pool and give them a queue
	for i in range(threads):
		t = Worker(queue, str(i))
		t.setDaemon(True)
		t.start()

	# give the queue some data
	for url in mapURL.values():
		queue.put(url)

	# wait for the queue to finish
	queue.join()

def main():
	mapURL = {}
	
	logo()
	parser = argparse.ArgumentParser(description='Ragpicker Malware Crawler')
	parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
	parser.add_argument("-t", "--threads", type=int, default=3, help="Threads to process (default=3, max=6)")
	parser.add_argument("-u", "--url", help="Download and analysis from a single URL")
	parser.add_argument('--log-level', default=logging.INFO, help='logging level, default=logging.INFO')
	parser.add_argument('--log-filename', help='logging filename')
	parser.add_argument('--version', action='version', version='Ragpicker version ' + RAGPICKER_VERSION)

	global args 
	args = parser.parse_args()
	
	if args.artwork:
		try:
			while True:
				time.sleep(1)
				logo()
		except KeyboardInterrupt:
			return
		
	if args.log_level:
		log_conf = dict(level=args.log_level,
			format='%(levelname)s %(name)s %(module)s:%(lineno)d %(message)s')

		if args.log_filename:
			log_conf['filename'] = args.log_filename
			log.info("log-filename: " + args.log_filename)

		logging.basicConfig(**log_conf)
	
	log.info("RAGPICKER_VERSION: " + RAGPICKER_VERSION)
	log.info("RAGPICKER_BUILD_DATE: " + RAGPICKER_BUILD_DATE)
	log.info("RAGPICKER_ROOT: " + RAGPICKER_ROOT)
	
	if args.url:
		log.info("Download and analysis from %s" % args.url)
		
		mapURL["0"] = args.url
		
		#Malware Download, process and reporting
		runWorker(mapURL, 1)
	else:
		#Max Threads=6
		if args.threads > 6:
			args.threads = 6
			
		log.info("Threads: " + str(args.threads))
			
		#Malware URLs Crawlen 
		mapURL = runCrawler()
		log.info("Process "+str(len(mapURL))+" URLs")
		
		#Malware Download, process and reporting
		runWorker(mapURL, args.threads)
	
if __name__ == "__main__":
	main()