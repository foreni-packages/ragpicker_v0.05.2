# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("Malc0deCrawler")

class Malc0de(IPlugin, Crawler):
     
    def run(self):
        self.mapURL = {} 
        mlc=[]
        mlc_sites=[]
        log.info("Fetching from Malc0de RSS")
        
        #parser
        soup = self.parse('http://malc0de.com/rss')
        
        for row in soup('description'):
            mlc.append(row)
        del mlc[0]
        
        for row in mlc:
            site = re.sub('&amp;','&',str(row).split()[1]).replace(',','')
            mlc_sites.append(site)
            
        log.info("Found %s urls" % len(mlc))
        
        for row in mlc_sites:
            self.storeURL(row)          
            
        return self.mapURL