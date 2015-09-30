# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import logging
import datetime
from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("SacourCrawler")

class Sacour(IPlugin, Crawler):
    now = datetime.datetime.now()  
    
    def run(self):
        self.mapURL = {}
        log.info("Fetching from Sacour.cn")
        
        #parser
        url = 'http://www.sacour.cn/showmal.asp?month=%d&year=%d'% (self.now.month, self.now.year)
        soup = self.parse(url)
        
        for url in soup('a'):
            min=[]
            try: 
                if re.match('list/',url['href']):
                    log.debug('-------- http://www.sacour.cn/'+url['href'])
                    suburl = self.parse('http://www.sacour.cn/'+url['href'])
                
                    for text in suburl('body'):
                        for urls in text.contents:
                            urls = str(urls).replace('\r\n', '')
                            if urls.startswith('http'):
                                log.debug(urls)
                                min.append(urls)
                
                if len(min) > 0:
                    log.info("-- Found %s urls in %s" % (len(min),url['href']))
                    for row in min:
                        self.storeURL(row)          
            except Exception as e:
                log.error('Error %s' % e.args)
        return self.mapURL