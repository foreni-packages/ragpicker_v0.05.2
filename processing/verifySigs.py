# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import time
import logging
import utils.verifySigs.fingerprint as fingerprint
import utils.verifySigs.auth_data as auth_data
import utils.verifySigs.pecoff_blob as pecoff_blob
from utils.verifySigs.asn1 import dn
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingVerifySigs")

class verifySigs(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "VerifySigs"
        self.score = -1
        #Dictionary containing all the results of this processing.
        self.results = {}   
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                self.verifySigs(objfile.temp_file)
                #No Validation-Exeption
                self.score = 0
            except Exception, msg:
                self.results["ValidationError"] = str(msg)
                self.score = 10
            
        return self.results
        
    def verifySigs(self, filePath):    
        """
        Verify-sigs - requires pyasn1 & m2crypto (apt-get insatll python-pyasn1 python-m2crypto)
        """
        with open(filePath, 'rb') as f:
            fingerprinter = fingerprint.Fingerprinter(f)
            is_pecoff = fingerprinter.EvalPecoff()
            fingerprinter.EvalGeneric()
            results = fingerprinter.HashIt()
    
            if is_pecoff:
                # using a try statement here because of: http://code.google.com/p/verify-sigs/issues/detail?id=2
                try:
                    fingerprint.FindPehash(results)
                except Exception, msg:
                    #Fehler bei Hashvalidierung
                    log.error("Hash validation error: %s" % msg)
                    raise Exception("Hash validation error: %s" % msg)
            
            signed_pecoffs = [x for x in results if x['name'] == 'pecoff' and 'SignedData' in x]
            
            if not signed_pecoffs:
                #Keine Signatur
                log.info('This PE/COFF binary has no signature. Exiting.')
                return
            
            try:
                #Validirungsfehler
                auth_data = self.validate(signed_pecoffs)
            except Exception, msg:
                log.error("Validate Error: %s" % msg)
                raise
            
            self.getAuthData(auth_data)
    
    def validate(self, signed_pecoffs):
        signed_pecoff = signed_pecoffs[0]
        signed_datas = signed_pecoff['SignedData']
        signed_data = signed_datas[0]
        blob = pecoff_blob.PecoffBlob(signed_data)
        auth = auth_data.AuthData(blob.getCertificateBlob())
        content_hasher_name = auth.digest_algorithm().name
        computed_content_hash = signed_pecoff[content_hasher_name]
        
        try:
            auth.ValidateAsn1()
            auth.ValidateHashes(computed_content_hash)
            auth.ValidateSignatures()
            auth.ValidateCertChains(time.gmtime())
        except auth_data.Asn1Error:
            if auth.openssl_error:
                log.info("OpenSSL Errors:\n%s" % auth.openssl_error)
            raise
        
        return auth
    
    def getAuthData(self, auth_data):
        self.results["ProgramName"] = auth_data.program_name
        self.results["ProgramURL"] = auth_data.program_url
        self.results["Issuer"] = self.issuerParser(str(auth_data.signing_cert_id))
        
        for (issuer, serial), cert in auth_data.certificates.items():
            subject = cert[0][0]['subject']
            subject_dn = dn.DistinguishedName.TraverseRdn(subject[0])
            self.results["PublisherCN"] = subject_dn['CN']
            self.results["PublisherO"] = subject_dn['O']
            
            not_before_time = self.formatTime(cert[0][0]['validity']['notBefore'])
            not_after_time = self.formatTime(cert[0][0]['validity']['notAfter'])
            self.results["NotBefore"] = not_before_time
            self.results["NotAfter"] = not_after_time
            break
    
    def formatTime(self, cert_time):
        cert_time = cert_time.ToPythonEpochTime()
        cert_time = time.strftime("%d.%m.%Y %H:%M:%S", time.gmtime(cert_time))
        return "%s UTC" % cert_time
        
    def issuerParser(self, issuedString):
        pattern = re.compile("'O':\s'(.*?)'.*", re.IGNORECASE)
        rpdFind = re.findall(pattern,issuedString)
        
        i=''
        for i in rpdFind:
            issuer = i
          
        return issuer
    