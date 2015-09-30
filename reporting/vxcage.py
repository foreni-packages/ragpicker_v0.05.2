# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import json
import urllib
import urllib2
from UserString import MutableString
from utils.multiPartForm import MultiPartForm
from core.abstracts import Report

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ReportingVxCage")

VXCAGE_URL_ADD = "http://%s:%s/malware/add"
VXCAGE_URL_FIND = "http://%s:%s/malware/find"


class VxCage(IPlugin, Report):
    """VxCage is a Python application for managing a malware samples repository.
    """
    
    def run(self, results, objfile):
        self.key = "VxCage"
        self.host = self.options.get("host")
        self.port = self.options.get("port")
        
        if not self.host or not self.port:
            raise Exception("VxCage REST API server not configurated")
        
        if objfile.is_permittedType() and self._isFileInCage(objfile.get_fileMd5()) == False:
            self._upload(results, objfile)
            
    def _upload(self, results, objfile):
        rawFile = open(objfile.temp_file, 'rb')
        file_extension = '.' + objfile.file_extension()
        fileName = objfile.get_fileMd5() + file_extension
        
        log.debug(VXCAGE_URL_ADD % (self.host, self.port) + " file=" + fileName)
        
        try:                
            form = MultiPartForm()
            form.add_file('file', fileName, fileHandle=rawFile)
            form.add_field('tags', self._getTags(results, objfile))
            
            request = urllib2.Request(VXCAGE_URL_ADD % (self.host, self.port))
            body = str(form)
            request.add_header('Content-type', form.get_content_type())
            request.add_header('Content-length', len(body))
            request.add_data(body)
            
            response_data = urllib2.urlopen(request).read() 
            reponsejson = json.loads(response_data)           
            log.info("Submitted to vxcage, message: %s", reponsejson["message"])   
        except urllib2.URLError as e:
            raise Exception("Unable to establish connection to VxCage REST API server: %s" % e)
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to VxCage REST API server (http code=%s)" % e) 
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
        
        if reponsejson["message"] != 'added':
            raise Exception("Failed to store file in VxCage: %s" % reponsejson["message"])
        
    def _isFileInCage(self, md5):
        param = { 'md5': md5 }
        request_data = urllib.urlencode(param)
        
        log.debug(VXCAGE_URL_FIND % (self.host, self.port) + " md5=" + md5)

        try:
            request = urllib2.Request(VXCAGE_URL_FIND % (self.host, self.port), request_data)
            response = urllib2.urlopen(request)
            response_data = response.read()
        except urllib2.HTTPError as e:
            if e.code == 404:
                #Error: 404 Not Found
                log.info('404 Not Found (md5=' + md5 + ')')
                return False
            else:
                raise Exception("Unable to perform HTTP request to VxCage (http code=%s)" % e)
        except urllib2.URLError as e:    
            raise Exception("Unable to establish connection to VxCage: %s" % e)  
        
        try:    
            check = json.loads(response_data)
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
            
        if check["md5"] == md5:
            log.info("File " + md5 + " is in VxCage")
            return True
        
        return False
    
    def _getTags(self, results, objfile):
        tags = MutableString()
        
        #Digital Signature
        #isProbablyPacked
        try:
            if results["Info"] and results["Info"]["file"]:
                tags += results["Info"]["file"]["digitalSignature"]
                tags += ", "
                tags += "isProbablyPacked: " + str(results["Info"]["file"]["isProbablyPacked"])
                tags += ", "
        except KeyError:
            # Key is not present
            pass

        #URL
        if results["Info"] and results["Info"]["url"]:
            tags += results["Info"]["url"]["hostname"]
            tags += ", "
        
        #Packer Ident
        if results.get("PEID", None):
            tags += results["PEID"][0]
            tags += ", "
        
        #AVIRA
        try:
            if results["AntivirusScanAvira"] and results["AntivirusScanAvira"]["Avira"]:
                tags += "Avira: " + results["AntivirusScanAvira"]["Avira"]["scan"]
                tags += ", "
        except KeyError:
            # Key is not present
            pass
        
        #CLAM-AV
        try:
            if results["AntivirusScanClamAv"] and results["AntivirusScanClamAv"]["ClamAv"]:
                tags += "ClamAv: " + results["AntivirusScanClamAv"]["ClamAv"]
                tags += ", "
        except KeyError:
            # Key is not present
            pass
    
        #VirusTotal
        try:
            if results["VirusTotal"] and results["VirusTotal"]["file"] and results["VirusTotal"]["file"]["positives"]:
                tags += "VirusTotal: "
                tags += results["VirusTotal"]["file"]["positives"]
                tags += "/"
                tags += results["VirusTotal"]["file"]["total"]
                tags += ", "
        except KeyError:
            # Key is not present
            pass
        
        #CountryCode
        try:
            if results["InetSourceAnalysis"] and results["InetSourceAnalysis"]["URLVoid"]:
                tags += results["InetSourceAnalysis"]["URLVoid"]["urlResult"][1]["CountryCode"]
                tags += ", "
        except KeyError:
            # Key is not present
            pass
        
        #FileType
        tags += objfile.get_type()
        tags += ", "
                
        tags += "ragpicker"
        
        log.info("tags=" + tags)
        
        return str(tags)