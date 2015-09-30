# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("TestCrawler")

class Test(IPlugin, Crawler):    
    
    def run(self):
        log.info("Fetching from localhost")
        self.mapURL = {}
        
        urls = self.options.get('url').split(',')
        
        for url in urls:
            log.info('URL=' + url)
            self.storeURL(url)          
            
        return self.mapURL