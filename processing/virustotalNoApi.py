# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import urllib2
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

try:
    from BeautifulSoup import BeautifulSoup as bs
except ImportError:
    raise ImportError, 'Beautiful Soup parser: http://www.crummy.com/software/BeautifulSoup/'

log = logging.getLogger("ProcessingVirustotalNoApi")

VIRUSTOTAL_FILE_URL = 'https://www.virustotal.com/de/search/?query=%s'

class VirustotalNoApi(IPlugin, Processing):
    
    # beautifulsoup parser
    def parse(self, url):
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
        try:
            http = bs(urllib2.urlopen(request, timeout=30))
        except Exception, e:
            log.error("%s - Error parsing %s" % (e, url))
            return
        return http 
    
    def run(self, objfile):
        self.key = "VirusTotal"
        self.score = -1
        returnValue = {}
        
        #Check file md5
        vt_file = self._vt_file(objfile)
        returnValue.update(vt_file)
        
        return returnValue
    
    def _fileFound(self, soup):
        s = soup.find("h2", { "class" : "alert-heading" })

        if s:
            s = str(s)
            i = s.find("Datei nicht gefunden")
            if i > 0:
                return False
        
        return True
    
    def _vt_file(self, objfile):
        returnValue = {}
        result = {}
        log.debug("MD5=%s" % objfile.get_fileMd5())
    
        #parser
        soup = self.parse(VIRUSTOTAL_FILE_URL % objfile.get_fileMd5())
        
        if self._fileFound(soup):
            try:
                s = soup.find(text='Erkennungsrate:')
                while getattr(s, 'name', None) != 'td':
                    s = s.next
                
                s = str(s.contents[0])
                s = s.replace('\n', "").replace(' ', "")
                
                s = s.split('/')
                
                positives = s[0]
                total = s[1]
                
                #calculate scoring
                if int(positives) == 0:
                    self.score = 0
                elif int(positives) <= 1:
                    self.score = 5
                elif int(positives) <= 2:
                    self.score = 8
                elif int(positives) >= 3:
                    self.score = 10
                    
                result["positives"] = positives
                result["total"] = total  
            except Exception, e:
                log.error("%s - Error Determining the detection rate" % e)
                return
            
            try:
                s = soup.find(text='Analyse-Datum:')
                while getattr(s, 'name', None) != 'td':
                    s = s.next
                
                s = str(s.contents[0])
                s = s.replace('\n', "").replace('  ', "").replace('( ', " ( ")
                
                result["scan_date"] = s
            except Exception, e:
                log.error("%s - Error Determining the scan date" % e)
                return
            
            try:
                s = soup.find(text="First submission").parent.parent.contents[2]
                s = str(s)
                s = s.replace('\n', "").replace('  ', "")
                
                result["first_submission"] = s
            except Exception, e:
                log.error("%s - Error Determining the First submission date" % e)
                return
        else: 
            result["verbose_msg"] = "Datei nicht gefunden"
            
        returnValue["file"] = result
        log.info(returnValue)
        return returnValue