# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import json
import urllib
import urllib2
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingVirusTotal")

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

class VirusTotal(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "VirusTotal"
        self.score = -1
        self.vtkey = self.options.get("apikey", None)
        returnValue = {}
        
        if not self.vtkey:
            raise Exception("VirusTotal API key not configured, skip")
        
        #Check file md5
        vt_file = self._vt_file(objfile)
        returnValue.update(vt_file)
        
        #Check URL-Hostname
        #vt_url = self._vt_url(objfile)
        #returnValue.update(vt_url)
        
        return returnValue
    
    def _vt_url(self, objfile):
        returnValue = {}

        log.info("URL=%s" % objfile.get_url_hostname())
        data = urllib.urlencode({"resource" : objfile.get_fileMd5(), "apikey" : self.vtkey})
        
        virustotal = self._process(VIRUSTOTAL_URL_URL, data)
        log.info("VT-URL: %s" % virustotal)

        result = {}
        result["response_code"] = virustotal["response_code"]
        
        #TODO URL-Response verareiten
        
        returnValue["url"] = result 
        
        return returnValue
    
    def _vt_file(self, objfile):
        returnValue = {}

        log.info("MD5=%s" % objfile.get_fileMd5())
        data = urllib.urlencode({"resource" : objfile.get_fileMd5(), "apikey" : self.vtkey})
        
        virustotal = self._process(VIRUSTOTAL_FILE_URL, data)
        log.info("VT-File: %s" % virustotal)

        result = {}
        result["response_code"] = virustotal["response_code"]
        
        if result["response_code"] == 1:
            result["scan_date"] = virustotal["scan_date"]
            result["positives"] = virustotal["positives"]    
            result["total"] = virustotal["total"]  
            
            #calculate scoring
            positives = int(virustotal["positives"]) 
            if positives == 0:
                self.score = 0
            elif positives > 0 and positives < 4:
                self.score = 8
            elif positives >= 4:
                self.score = 10     
        else:
            result["verbose_msg"] = virustotal["verbose_msg"]
                 
        returnValue["file"] = result 
        
        return returnValue
    
    def _process(self, url, data):
        try:
            request = urllib2.Request(url, data)
            response = urllib2.urlopen(request)
            response_data = response.read()
        except urllib2.URLError as e:
            raise Exception("Unable to establish connection to VirusTotal: %s" % e)
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to VirusTotal (http code=%s)" % e)

        try:
            virustotal = json.loads(response_data)
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
        
        return virustotal
        