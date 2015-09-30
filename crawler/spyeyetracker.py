# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("SpyEyetrackerCrawler")

class SpyEyetracker(IPlugin, Crawler):     
    
    def run(self):
        self.mapURL = {}
        log.info("Fetching from SpyEyetracker RSS")
        
        #parser
        soup = self.parse('https://spyeyetracker.abuse.ch/monitor.php?rssfeed=binaryurls')
        
        urls=[]
        for row in soup('description'):
            site = str(row).split()[2].replace(',','')
            urls.append(site)
        del urls[0]
        log.info("Found %s urls" % len(urls))
        for row in urls:
            log.debug(row)
            self.storeURL(row)          
            
        return self.mapURL