# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import re
import httplib2
import urllib
import urllib2
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

MALICIOUS = "Malicious"
log = logging.getLogger("ProcessingInetSourceAnalysis")

class InetSourceAnalysis(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "InetSourceAnalysis"
        self.score = -1
        self.hitcount = 0
        self.is_urlvoid = self.options.get("urlvoid", False)
        self.is_fortiguard = self.options.get("fortiguard", False)
        self.is_urlquery = self.options.get("urlquery", False)
        self.is_ipvoid = self.options.get("ipvoid", False)
        self.is_alienvault = self.options.get("alienvault", False)
        self.is_robtex = self.options.get("robtex", False)
        
        #IP-Adressen fuer weitere Analyse
        self.ip = []
        #Dictionary containing all the results of this processing.
        self.results = {}   
        
        input = objfile.get_url_hostname()
        
        rpIP = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
        rpdFindIP = re.findall(rpIP,input)
        rpdSortedIP=sorted(rpdFindIP)
        rpdSortedIP=str(rpdSortedIP)
        rpdSortedIP=rpdSortedIP[2:-2]
        
        if rpIP == input:
            log.info('%s is an IP.' % input)
            self._processIP(input)
        else:
            log.info('%s is a URL.' % input)
            self._processDomain(input)
            
        #calculate scoring
        self.score = self.hitcount * 2
        
        return self.results
    
    def _processIP(self, ip):
        if self.is_ipvoid:
            try:
                ipvoid = self._ipvoid(ip)   
                self.results["IPVoid"] = ipvoid   
            except Exception as e:
                log.error("Service IPVoid Failed: %s" % e)        
        
        if self.is_alienvault:
            try:
                alienvault = self._alienvault(ip)  
                self.results["Alienvault"] = alienvault 
            except Exception as e:
                log.error("Service Alienvault Failed: %s" % e)   
        
        if self.is_robtex:
            try:
                robtex = self._robtex(ip)   
                self.results["Robtex"] = robtex     
            except Exception as e:
                log.error("Service Robtex Failed: %s" % e)    

    def _processDomain(self, url):

        if self.is_fortiguard:
            try:
                fortiGuard = self._fortiURL(url)
                self.results["FortiGuard"] = fortiGuard
            except Exception as e:
                log.error("Service FortiGuard Failed: %s" % e)
        
        if self.is_urlvoid:
            try:
                urlvoid = self._urlvoid(url)
                self.results["URLVoid"] = urlvoid
            except Exception as e:
                log.error("Service URLVoid Failed: %s" % e)
        
        if self.is_urlquery:
            try:
                urlquery = self._urlquery(url)
                self.results["URLQuery"] = urlquery
            except Exception as e:
                log.error("Service URLQuery Failed: %s" % e)
        
        for ip in self.ip:
            self._processIP(ip)
            
    def _urlquery(self, urlInput):
        httplib2.debuglevel=4          
        
        url = "http://urlquery.net/%s"
        action_search = url % "search.php?q=%s" % urlInput
        
        conn = urllib2.urlopen(action_search)
        content2String = conn.read()      

        rpd = re.compile('.*&nbsp;&nbsp;0\sresults\sreturned*', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
    
        if not rpdFind:
            #Reports found
            log.debug('urlquery Reports found')
            self.hitcount += 1
            urlqueryResults = []
            
            rpd = re.compile("\shref='(.*?)'\>", re.IGNORECASE)
            rpdFindReport = re.findall(rpd,content2String)
            
            rpd = re.compile("\<td\>\<a\stitle='(.*?)'\shref='report.php", re.IGNORECASE)
            rpdFindReportUrl = re.findall(rpd,content2String)               
            
            rpd = re.compile("\<td\salign='center'\>\<b\>(.*?)\<\/b\>\<\/td\>", re.IGNORECASE)
            rpdFindAlertsIDS = re.findall(rpd,content2String)    
            
            rpd = re.compile("\<td\>\<nobr\>\<center\>(.*?)\<\/center\>\<\/nobr\>\<\/td\>", re.IGNORECASE)
            rpdFindDatum = re.findall(rpd,content2String)    
            
            rpd = re.compile("align='left'\stitle='(.*?)'\swidth='\d{2}'\sheight='\d{2}'\s/>", re.IGNORECASE)
            rpdFindLand = re.findall(rpd,content2String)   
        
            i = 0
            datum=''
            for datum in rpdFindDatum:   
                result = {} 
                result["datum"] = datum    
                result["alerts_ids"] = rpdFindAlertsIDS[i]
                result["country"] = rpdFindLand[i]
                result["reportUrl"] = rpdFindReportUrl[i].encode('ascii', 'replace')
                result["report"] = url % rpdFindReport[i]   
                urlqueryResults.append(result)                   
                i += 1             

            urlquery = {'url':urlInput, 'urlResult':urlqueryResults}
        else:   
            log.debug('urlquery Reports NOT found')  
            urlquery = {'url': urlInput, 'urlResult' : 'NOT listed'}     
            
        return urlquery
    
    def _fortiURL(self, urlInput): 
        httplib2.debuglevel=4          
        
        conn = urllib2.urlopen("http://www.fortiguard.com/ip_rep.php?data=" + urlInput + "&lookup=Lookup")
        content2String = conn.read()        
        
        rpd = re.compile('h3\sstyle\=\"float:\sleft\"\>Category:\s(.+)\<\/h3', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSorted=sorted(rpdFind)

        m=''
        for m in rpdSorted:
            fortiGuard = urlInput + " Categorization: " + m  
            
            if MALICIOUS in m:
                self.hitcount += 1
        if m=='':
            fortiGuard = urlInput + " Categorization: Uncategorized"   
            
            
            
        return fortiGuard

    def _urlvoid(self, urlInput):    
        httplib2.debuglevel=4 
        conn = urllib2.urlopen("http://urlvoid.com/scan/" + urlInput)
        content2String = conn.read()            
        
        rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
        rpdFinderr = re.findall(rpderr,content2String)
        
        if "ERROR" in str(rpdFinderr):
            _urlvoid = ('http://www.urlvoid.com/')
            raw_params = {'url':urlInput,'Check':'Submit'}
            params = urllib.urlencode(raw_params)
            request = urllib2.Request(_urlvoid,params,headers={'Content-type':'application/x-www-form-urlencoded'})
            page = urllib2.urlopen(request)
            page = page.read()
            content2String = str(page)
   
        rpd = re.compile('title=\"Find\swebsites\shosted\shere\"\><strong\>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortedIP=sorted(rpdFind) 
        
        rpd = re.compile('color..red..DETECTED..font...td..td..a.rel..nofollow..href.\"(.{6,120})\"\stitle', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortBlacklist=sorted(rpdFind)  
        
        rpd = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortCountry=sorted(rpdFind)
        
        rpd = re.compile('HTTP\sResponse\sCode\<\/td\>\<td\>\<img\ssrc=.{1,100}\salt=".{5}"\s\/\>(.+)\<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortHTTPResponseCode=sorted(rpdFind)
        
        rpd = re.compile('\<h3\sclass=\"detected_website\"\>(.+)\<\/h3\>', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortWebsiteStatus=sorted(rpdFind)             
        
        urlResult = []
        
        i=''
        for i in rpdSortedIP:
            urlResult.append({"IP" : i})
            #IP fuer weitere Analyse Speichern
            self.ip.append(i)
        if i=='':
            urlResult.append({"IP" : "Host IP Address is not listed"})
        
        l=''
        for l in rpdSortCountry:
            urlResult.append({"CountryCode" : l.strip()})
        if l=='':
            urlResult.append({"CountryCode" : "No Country listed"}) 
            
        m=''
        for m in rpdSortHTTPResponseCode:
            urlResult.append({"HTTPResponseCode" : m})
        if m=='':
            urlResult.append({"HTTPResponseCode" : 'HTTP-Response-Code not listed.'})
        n=''
        for n in rpdSortWebsiteStatus:
            urlResult.append({"WebsiteStatus" : n})
            #URL blacklisted
            self.hitcount += 1
        if n=='':
            urlResult.append({"WebsiteStatus" : 'The website is not blacklisted.'})          
        j=''
        for j in rpdSortBlacklist:
            urlResult.append({"Blacklist" : 'Host is listed in blacklist at: ' + j})
        if j=='':
            urlResult.append({"Blacklist" : 'Host is not listed in a blacklist'})              

        return {"url" : urlInput, "urlResult" : urlResult}
        
    def _ipvoid(self, ipInput):
        httplib2.debuglevel=4     
        
        conn = urllib2.urlopen("http://ipvoid.com/scan/" + ipInput)
        content2String = conn.read()            
        
        rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
        rpdFinderr = re.findall(rpderr,content2String)
        
        if "ERROR" in str(rpdFinderr):
            _ipvoid = ('http://www.ipvoid.com/')
            raw_params = {'ip':ipInput,'go':'Scan Now'}
            params = urllib.urlencode(raw_params)
            request = urllib2.Request(_ipvoid,params,headers={'Content-type':'application/x-www-form-urlencoded'})
            page = urllib2.urlopen(request)
            page = page.read()
            content2String = str(page)      
              
        rpd = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortBlacklist=sorted(rpdFind)
        
        rpd = re.compile('\<tr\>\<td\>Blacklist\sStatus\<\/td\>\<td\>\<span\sclass=\"blacklist_status_.{3,4}\">(.+)\<\/span\>\<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortBlacklistStatus=sorted(rpdFind)        
    
        rpd = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>\<\/tr\>\<tr\>\<td\>Continent', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortISP=sorted(rpdFind)
    
        rpd = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>\<\/tr\>\<tr\>\<td\>Latitude', re.IGNORECASE)
        rpdFind = re.findall(rpd,content2String)
        rpdSortGeoLoc=sorted(rpdFind)

        ipResult = []
        
        i=''
        for i in rpdSortBlacklistStatus:
            ipResult.append({"BlacklistStatus" : i})
            
            if "NOT BLACKLISTED" not in i:
                #IP ist blacklisted
                self.hitcount += 1
        if i=='':
            ipResult.append({"BlacklistStatus" : 'No Blacklist status'})         
        
        j=''
        for j in rpdSortBlacklist:
            ipResult.append({"Blacklist" : 'Host is listed in blacklist at: '+ j})
        if j=='':
            ipResult.append({"Blacklist" : 'Host is not listed in a blacklist'})   
       
        k=''
        for k in rpdSortISP:
            ipResult.append({"ISP" : 'The ISP for this IP is: ' + k})
        if k=='':
            ipResult.append({"ISP" : 'No ISP listed'})
        
        l=''
        for l in rpdSortGeoLoc:
            ipResult.append({"GEOLocation" : l})
        if l=='':
            ipResult.append({"GEOLocation" : 'No GEO location listed'})          

        return {"ip" : ipInput, "ipResult" : ipResult}
        
    def _alienvault(self, ipInput):
        httplib2.debuglevel=4 
        
        url = "http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip=" + ipInput
        conn = urllib2.urlopen(url)
        content2String = conn.read()  
        
        rpd = re.compile('.*IP not found.*')
        rpdFind = re.findall(rpd, content2String)
    
        if not rpdFind:
            alienvault = ipInput + ' is listed in AlienVault-Database: ' + url
            self.hitcount += 1
        else:           
            alienvault = ipInput + ' is not listed in AlienVault IP reputation database' 
            
        return alienvault
    
    def _robtex(self, ipInput):
        httplib2.debuglevel=4 
            
        conn = urllib2.urlopen("http://robtex.com/" + ipInput)
        content2String = conn.read()          
        
        rpd = re.compile('host\.robtex\.com.+\s\>(.+)\<\/a\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        
        rpdSorted=sorted(rpdFind)
        
        ipResult = []
        
        i=''
        for i in rpdSorted:
            if len(i)>4:
                if not i == ipInput:
                    ipResult.append({"ARecord" : (i)})
        if i=='':
            ipResult.append({"ARecord" : "This IP does not resolve to a domain"})     
        
        return {"ip" : ipInput, "ipResult" : ipResult}             
            
    def _checkIP(self, ipAdress):
        #ToDo in config auslagern
        if len(ipAdress) >0 and ipAdress.find("192.168.") == -1 and ipAdress.find("8.8.8.8") == -1:
            return True
        
    def _isInURLVoid(self, ipAdress):
        for obj in self.ip:
            if ipAdress == obj:
                return True
        return False