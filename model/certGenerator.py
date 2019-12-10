import os
import collections
import subprocess
import json
import re

class certStructure(object):

     def __init__(self, data = {}):
          self.certData = collections.defaultdict(str)
          self.certData.update(data)

          if self.certData['outputDirName'] == '':
               self.certData['outputDirName'] = 'certificates'

class certificateAuthorityStructure(certStructure):

     def __init__(self, data = {}):
          super(certificateAuthorityStructure, self).__init__(data)
          if self.certData['customerType'] == '':
               self.certData['customerType'] = 'UUT'

     def setCommand(self, opensslCmd):
          subprocess.call(opensslCmd, shell = True)

     def setKey(self, config):
          opensslCmd = self.getOpensslKeyCmd(config)
          self.setCommand(opensslCmd)
     
     def setRootCert(self, config):
          certImformation = self.getCertInformation(config)
          opensslCmd = self.getOpensslRootCertCmd(config, certImformation)
          self.setCommand(opensslCmd)

     def setCsr(self, config):
          certImformation = self.getCertInformation(config)
          opensslCmd = self.getOpensslCsrCmd(config, certImformation)
          self.setCommand(opensslCmd)

     def setCert(self, config):
          opensslCmd = self.getOpensslCertCmd(config)
          self.setCommand(opensslCmd)
     
     def getOpensslKeyCmd(self, config):
          return ['openssl','genrsa','-out', config['key'], config['keysize']]
     
     def getOpensslRootCertCmd(self, config, certImformation):
          return ['openssl','req','-new','-x509','-key', config['key'],'-out', config['cert'], '-days', config['validity'],'-subj', certImformation,'-config', config['configFile']]

     def getOpensslCsrCmd(self, config, certImformation):
          return ['openssl','req','-new','-key', config['key'],'-out', config['csr'],'-subj', certImformation, '-config', config['configFile']]

     def getOpensslCertCmd(self, config):
          return ['openssl', 'x509', '-req', '-in', config['csr'], '-CA', config['parentCert'], '-CAkey', config['parentkey'], '-CAcreateserial','-out', config['cert'],'-days', config['validity'], '-sha384','-extfile', config['configFile'], '-extensions', config['extensions']]
     
     def getCertInformation(self, config):
          return '/C='+config['countryName']+'/O='+config['organizationName']+'/OU='+config['organizationUnitName']+'/CN='+config['commonName']

class certGeneratorModel(certStructure):

     def __init__(self, data = {}):
          super(certGeneratorModel, self).__init__(data)
          self.rootPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\' + self.certData['outputDirName']
          self.rawCertPath = self.rootPath + '\\OriginalCerts'
          self.outputUUTCertPath = self.rootPath + '\\ManagedCerts\\UUT'
          self.outputHarnessCertPath = self.rootPath + '\\ManagedCerts\\SAS-Test-Harness'
          self.makeDir()
          self.setConfig()

     def removeDir(self):
          subprocess.call('rmdir '+str(self.rootPath)+' /s /q', shell = True)

     def makeDir(self):
          # remove dir which has the same name
          if os.path.isdir(str(self.rootPath)): self.removeDir()

          subprocess.call('mkdir ' + str(self.outputUUTCertPath), shell = True)
          subprocess.call('mkdir ' + str(self.outputHarnessCertPath) + '\\SCS1', shell = True)
          subprocess.call('mkdir ' + str(self.outputHarnessCertPath) + '\\SCS2', shell = True)
          subprocess.call('mkdir ' + str(self.outputHarnessCertPath) + '\\SCS3', shell = True)
          subprocess.call('mkdir ' + str(self.outputHarnessCertPath) + '\\SCS4', shell = True)
          subprocess.call('mkdir ' + str(self.outputHarnessCertPath) + '\\SCS5', shell = True)

          # to work with config/opensslcbrs1.cnf
          subprocess.call('mkdir '+str(self.rawCertPath) + '\\etc\\pki\\CA', shell = True)

     def setConfig(self):
          configPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\config'
          with open(configPath + '\\cert.json', 'r') as json_file:  
               self.certNameConfig = json.load(json_file)
          self.configFile = configPath + '\\' + self.certNameConfig['ConfigFile']['config']

     def setCertificateAuthority(self):
          Root_CA_config = self.getCertificateAuthorityConfig("Root")
          self.Root_CA = certificateAuthorityStructure(Root_CA_config)

     def getCertificateAuthorityConfig(self, name):
          config = collections.defaultdict(str)
          config.update(self.certNameConfig["CA_Default"])
          config.update(self.certNameConfig[name + "_CA"])
          return config










     def setRoot(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['Root_CA']['organization']+'/OU='+nameConfig['Root_CA']['OU']+'/CN='+nameConfig['Root_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['Root_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-x509','-key', nameConfig['Root_CA']['key'],'-out', nameConfig['Root_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-subj', certinformation,'-config', configFile], shell = True)

     def setSAS_CertificateAuthority(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['CA_Default']['organization']+'/OU='+nameConfig['SAS_CA']['OU']+'/CN='+nameConfig['SAS_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['SAS_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['SAS_CA']['key'],'-out', nameConfig['SAS_CA']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['SAS_CA']['csr'],'-CA', nameConfig['Root_CA']['cert'],'-CAkey', nameConfig['Root_CA']['key'],'-CAcreateserial','-out', nameConfig['SAS_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-sha384','-extfile', configFile, '-extensions', 'cbrs_sas_ca'], shell = True)

     def setCBSD_CertificateAuthority(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['CA_Default']['organization']+'/OU='+nameConfig['CBSD_CA']['OU']+'/CN='+nameConfig['CBSD_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['CBSD_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['CBSD_CA']['key'],'-out', nameConfig['CBSD_CA']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['CBSD_CA']['csr'],'-CA', nameConfig['Root_CA']['cert'],'-CAkey', nameConfig['Root_CA']['key'],'-CAcreateserial','-out', nameConfig['CBSD_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-sha384','-extfile', configFile, '-extensions', 'cbrs_cbsd_mfr_ca'], shell = True)

     def setDomainProxy_CertificateAuthority(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['CA_Default']['organization']+'/OU='+nameConfig['DP_CA']['OU']+'/CN='+nameConfig['DP_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['DP_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['DP_CA']['key'],'-out', nameConfig['DP_CA']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['DP_CA']['csr'],'-CA', nameConfig['Root_CA']['cert'],'-CAkey', nameConfig['Root_CA']['key'],'-CAcreateserial','-out', nameConfig['DP_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-sha384','-extfile', configFile, '-extensions', 'cbrs_domain_proxy_ca'], shell = True)

     def setUnknownSAS_CertificateAuthority(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['CA_Default']['organization']+'/OU='+nameConfig['SAS_Unknown_CA']['OU']+'/CN='+nameConfig['SAS_Unknown_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['SAS_Unknown_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['SAS_Unknown_CA']['key'],'-out', nameConfig['SAS_Unknown_CA']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['SAS_Unknown_CA']['csr'],'-CA', nameConfig['Root_CA']['cert'],'-CAkey', nameConfig['Root_CA']['key'],'-CAcreateserial','-out', nameConfig['SAS_Unknown_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-sha384','-extfile', configFile, '-extensions', 'cbrs_sas_ca'], shell = True)

     def setCPI_CertificateAuthority(self, nameConfig, configFile):
          certinformation = '/C='+nameConfig['CA_Default']['country']+'/O='+nameConfig['CPI_CA']['organization']+'/OU='+nameConfig['CPI_CA']['OU']+'/CN='+nameConfig['CPI_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['CPI_CA']['key'], nameConfig['CA_Default']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['CPI_CA']['key'],'-out', nameConfig['CPI_CA']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['CPI_CA']['csr'],'-CA', nameConfig['Root_CA']['cert'],'-CAkey', nameConfig['Root_CA']['key'],'-CAcreateserial','-out', nameConfig['CPI_CA']['cert'],'-days', nameConfig['CA_Default']['validity'],'-sha384','-extfile', configFile, '-extensions', 'professional_installer_ca'], shell = True)

     def setSAS_Certificates(self, nameConfig, configFile):
          ## Harness Certificate
          certinformation = '/C='+nameConfig['CertificateDefault']['country']+'/O='+nameConfig['Harness_Certificate']['organization']+'/OU='+nameConfig['CertificateDefault']['OU']+'/CN='+nameConfig['Harness_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['Harness_Certificate']['key'], nameConfig['CertificateDefault']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['Harness_Certificate']['key'],'-out', nameConfig['Harness_Certificate']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['Harness_Certificate']['csr'],'-CA', nameConfig['SAS_CA']['cert'],'-CAkey', nameConfig['SAS_CA']['key'],'-CAcreateserial','-out', nameConfig['Harness_Certificate']['cert'],'-days', nameConfig['CertificateDefault']['validity'],'-sha256','-extfile', configFile, '-extensions', 'sas_cert'], shell = True)
          
          ## Harness Unknown Certificate
          certinformation = '/C='+nameConfig['CertificateDefault']['country']+'/O='+nameConfig['CertificateDefault']['organization']+'/OU='+nameConfig['CertificateDefault']['OU']+'/CN='+nameConfig['Harness_Unknown_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['Harness_Unknown_Certificate']['key'], nameConfig['CertificateDefault']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['Harness_Unknown_Certificate']['key'],'-out', nameConfig['Harness_Unknown_Certificate']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['Harness_Unknown_Certificate']['csr'],'-CA', nameConfig['SAS_Unknown_CA']['cert'],'-CAkey', nameConfig['SAS_Unknown_CA']['key'],'-CAcreateserial','-out', nameConfig['Harness_Unknown_Certificate']['cert'],'-days', nameConfig['CertificateDefault']['validity'],'-sha256','-extfile', configFile, '-extensions', 'sas_cert'], shell = True)

          ## Harness Expired Certificate
          certinformation = '/C='+nameConfig['CertificateDefault']['country']+'/O='+nameConfig['CertificateDefault']['organization']+'/OU='+nameConfig['CertificateDefault']['OU']+'/CN='+nameConfig['Harness_Expire_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['Harness_Expire_Certificate']['key'], nameConfig['CertificateDefault']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['Harness_Expire_Certificate']['key'],'-out', nameConfig['Harness_Expire_Certificate']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['Harness_Expire_Certificate']['csr'],'-CA', nameConfig['SAS_CA']['cert'],'-CAkey', nameConfig['SAS_CA']['key'],'-CAcreateserial','-out', nameConfig['Harness_Expire_Certificate']['cert'],'-days', nameConfig['Harness_Expire_Certificate']['validity'],'-sha256','-extfile', configFile, '-extensions', 'sas_cert'], shell = True)

          ## Harness Revoke Certificate
          certinformation = '/C='+nameConfig['CertificateDefault']['country']+'/O='+nameConfig['CertificateDefault']['organization']+'/OU='+nameConfig['CertificateDefault']['OU']+'/CN='+nameConfig['Harness_Revoke_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', nameConfig['Harness_Revoke_Certificate']['key'], nameConfig['CertificateDefault']['keysize']], shell = True)
          subprocess.call(['openssl','req','-new','-key', nameConfig['Harness_Revoke_Certificate']['key'],'-out', nameConfig['Harness_Revoke_Certificate']['csr'],'-subj', certinformation,'-config', configFile], shell = True)
          subprocess.call(['openssl','x509','-req','-in', nameConfig['Harness_Revoke_Certificate']['csr'],'-CA', nameConfig['SAS_CA']['cert'],'-CAkey', nameConfig['SAS_CA']['key'],'-CAcreateserial','-out', nameConfig['Harness_Revoke_Certificate']['cert'],'-days', nameConfig['CertificateDefault']['validity'],'-sha256','-extfile', configFile, '-extensions', 'sas_cert_with_crl'], shell = True)

          ## Harness Broken Certificate
          self.setBrokenCertificate(nameConfig['Harness_Certificate']['cert'], nameConfig['Harness_Broken_Certificate']['cert'])

     def setBrokenCertificate(self, orifile, brokefile):
          file_data = ""
          with open(orifile, "r") as f:
               for line in f:
                    file_data += line

          with open(brokefile , "w") as f:
               f.write(file_data)

     def setCertChain(self, filename, cert1, cert2):
          file_data = ""
          with open(cert1 , "r") as f:
               for line in f:
                    file_data += line

          with open(cert2, "r") as f:
               for line in f:
                    file_data += line
          
          with open(filename, "w+") as f:
               for line in file_data:
                    f.writelines(line)

     def setCRLprefile(self, path):
          file = open(path + "/index.txt", "w")
          file.close()
          file = open(path + "/crlnumber", "w")
          file.write("01")
          file.close()

     def setCustomerCertificates(self, nameConfig, configFile):
          keyName = self.setCustomerKey(self.certData['customerType'], nameConfig, configFile)
          csrName = self.setCustomerCsr(self.certData['customerType'], keyName, nameConfig, configFile)
          self.setCustomerCert(self.certData['customerType'], csrName, nameConfig, configFile)

     def getCustomerKey(self, customerType, nameConfig, configFile):
          keyFile = ""
          customerPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\customerfile'
          if self.certData['customerFile'] != '' and re.search(r'.key$', self.certData['customerFile'], 0):
               keyFile = customerPath + self.certData['customerFile']
          else :
               # self.setCustomerKey()
               pass


     def setCustomerKey(self, customerType, nameConfig, configFile):
          customerPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\customerfile'
          if self.certData['customerFile'] != '' and re.search(r'.key$', self.certData['customerFile'], 0):
               keyFile = customerPath + self.certData['customerFile']
               subprocess.call(['openssl','genrsa','-out', keyFile, nameConfig['CertificateDefault']['keysize']])
          else :
               keyFile = nameConfig[customerType + '_certificate']['key']
               subprocess.call(['openssl','genrsa','-out', keyFile, nameConfig['CertificateDefault']['keysize']])
          return keyFile

     def setCustomerCsr(self, customerType, keyName, nameConfig, configFile):
          pass

     def setCustomerCert(self, customerType, csrName, nameConfig, configFile):
          pass


class certGeneratorInterface(certGeneratorModel):

     pass

     
