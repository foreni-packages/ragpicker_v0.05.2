# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("CleanmxCrawler")

class Cleanmx(IPlugin, Crawler):
    
    def run(self):
        self.mapURL = {}
        urls=[]
        log.info("Fetching from Cleanmx RSS")
        
        #parser
        soup = self.parse('http://support.clean-mx.de/clean-mx/xmlviruses.php?')
        
        for row in soup('url'):
            try:
                urls.append(row.string)
            except Exception as e:
                log.error('Error in get from soup: (%s)', e)
                
        log.info("Found %s urls" % len(urls))
        
        for row in urls:            
            self.storeURL(row)          

        return self.mapURL