# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import logging
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("MinotaurCrawler")

class Minotaur(IPlugin, Crawler):      
    
    def run(self):
        self.mapURL = {}
        min=[]
        log.info("Fetching from Minotaur List")
        
        #parser
        soup = self.parse('http://minotauranalysis.com/malwarelist-urls.aspx')
        
        for row in soup('td'):
            try:
                if re.match('http',row.string):
                    min.append(row.string)
            except:
                pass
            
        log.info("Found %s urls" % len(min))
        
        for row in min: 
            self.storeURL(row)          
            
        return self.mapURL