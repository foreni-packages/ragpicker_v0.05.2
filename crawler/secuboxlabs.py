# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("SecuboxlabsCrawler")

class Secuboxlabs(IPlugin, Crawler):  
    
    def run(self):
        self.mapURL = {}
        log.info("Fetching from secuboxlabs.fr")
        
        #parser
        soup = self.parse('http://secuboxlabs.fr/152caf4d68ad169e7ffc370afa4f2939.rss')
        
        sbl=[]
        
        for row in soup('description'):
            for x in re.findall("malware://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]", str(row)):
                site = x.replace('malware://','http://')
                sbl.append(site)
        log.info("Found %s urls" % len(sbl))
        for row in sbl:
            self.storeURL(row)          
            
        return self.mapURL