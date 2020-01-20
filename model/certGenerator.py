# -*- coding: UTF-8 -*-
import os, sys
import collections
import subprocess
import json
import re
import glob 
os.chdir(os.path.abspath(os.path.dirname(__file__)))
from logger import logger

class certStructure(object):

     def __init__(self, data = {}):
          self.certData = collections.defaultdict(str)
          self.certData.update(data)

class certificateAuthorityStructure(certStructure):

     def __init__(self, data = {}):
          super(certificateAuthorityStructure, self).__init__(data)
          self.logger = logger("CertificateAuthorityStructure's Log >>")

     def setCommand(self, opensslCmd):
          subprocess.call(opensslCmd, shell = True)

     # Tier 1
     
     def setKey(self, config = {}):
          if not config:
               config = self.certData
          if self.isKeyConfigValid(config):
               opensslCmd = self.getOpensslKeyCmd(config)
               self.setCommand(opensslCmd)
     
     def setRootCert(self, config = {}):
          if not config:
               config = self.certData
          if self.isRootCertConfigValid(config) and self.isCertInformationConfigValid(config):
               certImformation = self.getCertInformation(config)
               opensslCmd = self.getOpensslRootCertCmd(config, certImformation)
               self.setCommand(opensslCmd)

     def setCsr(self, config = {}):
          if not config:
               config = self.certData
          if self.isCsrConfigValid(config) and self.isCertInformationConfigValid(config):
               certImformation = self.getCertInformation(config)
               opensslCmd = self.getOpensslCsrCmd(config, certImformation)
               self.setCommand(opensslCmd)

     def setCert(self, config = {}):
          if not config:
               config = self.certData
          if self.isCertConfigValid(config):
               opensslCmd = self.getOpensslCertCmd(config)
               self.setCommand(opensslCmd)

     def initCRL(self, config = {}):
          config.update(self.certData)
          if self.isInitCRLConfigValid(config):
               self.setCommand(self.getOpensslInitCRLCmd(config))

     def revokeCertificate(self, config = {}):
          config.update(self.certData)
          if self.isRevokeConfigValid(config):
               self.setCommand(self.getOpensslRevokeCmd(config))
               self.setCommand(self.getOpensslUpdatedCRLCmd(config))

     # Tier 2

     def isKeyConfigValid(self, config):
          keyList = ['key', 'keysize']
          return self.isConfigValid(config, keyList)
     
     def getOpensslKeyCmd(self, config):
          return ['openssl','genrsa','-out', config['key'], config['keysize']]     

     
     def isCertInformationConfigValid(self, config):
          Valid = True
          keyList = ['countryName', 'organizationName', 'organizationUnitName', 'commonName']
          if self.isConfigValid(config, keyList):
               if len(config['countryName']) != 2:
                    self.logger.setScreenPrint('Country name must be two characters')
                    Valid = False
          else:
               Valid = False
          return Valid

     def getCertInformation(self, config):
          return '/C='+config['countryName']+'/O='+config['organizationName']+'/OU='+config['organizationUnitName']+'/CN='+config['commonName'] 
     
     
     def isRootCertConfigValid(self, config):
          keyList = ['key', 'cert', 'validity', 'configFile']
          if not self.isConfigValid(config, keyList): return False
          fileNameList = [config['key']]
          return self.isPrefileExist(fileNameList)
     
     def getOpensslRootCertCmd(self, config, certImformation):
          return ['openssl','req','-new','-x509','-key', config['key'],'-out', config['cert'], '-days', config['validity'],'-subj', certImformation,'-config', config['configFile']]
    

     def isCsrConfigValid(self, config):
          keyList = ['key', 'csr', 'configFile']
          if not self.isConfigValid(config, keyList): return False
          fileNameList = [config['key']]
          return self.isPrefileExist(fileNameList)

     def getOpensslCsrCmd(self, config, certImformation):
          return ['openssl','req','-new','-key', config['key'],'-out', config['csr'],'-subj', certImformation, '-config', config['configFile']]


     def isCertConfigValid(self, config):
          keyList = ['csr', 'parentCert', 'parentKey', 'cert', 'validity', 'extensions']
          if not self.isConfigValid(config, keyList): return False
          fileNameList = [config['csr'], config['parentCert'], config['parentKey']]
          return self.isPrefileExist(fileNameList)
     
     def getOpensslCertCmd(self, config):
          return ['openssl','x509','-req','-in', config['csr'], '-CA', config['parentCert'], '-CAkey', config['parentKey'], '-CAcreateserial','-out', config['cert'],'-days', config['validity'], '-sha384','-extfile', config['configFile'], '-extensions', config['extensions']]
     

     def isInitCRLConfigValid(self, config):
          keyList = ['configFile', 'key', 'cert', 'emptycrl']
          if not self.isConfigValid(config, keyList): return False
          fileNameList = [config['configFile'], config['key'], config['cert']]
          return self.isPrefileExist(fileNameList)

     def getOpensslInitCRLCmd(self, config):
          return ['openssl','ca','-config', config['configFile'],'-gencrl','-keyfile', config['key'],'-cert', config['cert'],'-out', config['emptycrl']]

     def isRevokeConfigValid(self, config):
          keyList = ['configFile', 'key', 'cert', 'revokeCert', 'servercrl']
          if not self.isConfigValid(config, keyList): return False
          fileNameList = [config['configFile'], config['key'], config['cert'], config['revokeCert']]
          return self.isPrefileExist(fileNameList)

     def getOpensslRevokeCmd(self, config):
          return ['openssl','ca','-revoke', config['revokeCert'],'-config', config['configFile'],'-keyfile', config['key'],'-cert', config['cert']]

     def getOpensslUpdatedCRLCmd(self, config):
          return ['openssl','ca','-config', config['configFile'],'-gencrl','-keyfile', config['key'],'-cert', config['cert'],'-out', config['servercrl']]


     # Tier 3     
     
     def isUnsignedInt(self, val):
          try: 
               if int(val) > 0:
                    return True
               else:
                    return False
          except ValueError:
               return False

     def isConfigValid(self, config, keyList):
          Valid = True
          data = collections.defaultdict(str)
          data.update(config)
          for key in keyList:
               if data[key] == '':
                    self.logger.setScreenPrint(key + ': not found')
                    Valid = False
                    break
               if key == 'validity':
                    if not self.isUnsignedInt(data[key]):
                         self.logger.setScreenPrint('validity not right : ' + data[key])
                         Valid = False
                         break
          return Valid

     def isPrefileExist(self, fileNameList):
          Exist = True
          for key in fileNameList:
               if not os.path.isfile(key):
                    self.logger.setScreenPrint(key + ': File not exist')
                    Exist = False
                    break
          return Exist

class certGeneratorModel(certStructure):

     def __init__(self, data = {}):
          super(certGeneratorModel, self).__init__(data)
          if self.certData['outputDirName'] == '' : self.certData['outputDirName'] = 'certificates'
          if self.certData['customerType'] == ''  : self.certData['customerType'] = 'CBSD'
          self.rootPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\' + self.certData['outputDirName']
          self.rawCertPath = self.rootPath + '\\OriginalCerts'
          self.outputUUTCertPath = self.rootPath + '\\ManagedCerts\\UUT'
          self.outputHarnessCertPath = self.rootPath + '\\ManagedCerts\\SAS-Test-Harness'
          self.makeDir()
          self.setConfig()

     def removeDir(self):
          subprocess.call('rmdir ' + os.path.abspath(self.rootPath) + ' /s /q', shell = True)

     def makeDir(self):
          # remove dir which has the same name
          self.removeDir()

          subprocess.call('mkdir ' + os.path.abspath(self.outputUUTCertPath), shell = True)
          subprocess.call('mkdir ' + os.path.abspath(self.outputHarnessCertPath) + '\\SCS1', shell = True)
          subprocess.call('mkdir ' + os.path.abspath(self.outputHarnessCertPath) + '\\SCS2', shell = True)
          subprocess.call('mkdir ' + os.path.abspath(self.outputHarnessCertPath) + '\\SCS3', shell = True)
          subprocess.call('mkdir ' + os.path.abspath(self.outputHarnessCertPath) + '\\SCS4', shell = True)
          subprocess.call('mkdir ' + os.path.abspath(self.outputHarnessCertPath) + '\\SCS5', shell = True)

          # to work with config/opensslcbrs1.cnf
          subprocess.call('mkdir ' + os.path.abspath(self.rawCertPath) + '\\etc\\pki\\CA', shell = True)

     def setConfig(self):
          configPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\config'
          with open(configPath + '\\cert.json', 'r') as json_file:  
               self.certNameConfig = json.load(json_file)
          self.configFile = configPath + '\\' + self.certNameConfig['ConfigFile']['config']

     def setToRawCertPath(self):
          os.chdir(os.path.abspath(self.rawCertPath))

     def setRootCA(self):
          self.setToRawCertPath()
          Root_CA_config = self.getCertificateAuthorityConfig("Root")
          self.Root_CA = certificateAuthorityStructure(Root_CA_config)
          self.Root_CA.setKey()
          self.Root_CA.setRootCert()

     def setCertificateAuthority(self):
          self.setToRawCertPath()
          self.SAS_CA = self.getCertificateAuthority("SAS", "Root")
          self.unknownSAS_CA = self.getCertificateAuthority("SAS_Unknown", "Root")
          self.CPI_CA = self.getCertificateAuthority("CPI", "Root")
          self.CBSD_CA = self.getCertificateAuthority("CBSD", "Root")
          self.DP_CA = self.getCertificateAuthority("DP", "Root")

          self.UUT_CA = self.CBSD_CA if self.certData['customerType'] == "CBSD" else self.DP_CA

     def setCertificate(self):
          self.setToRawCertPath()
          self.SAS_harness_Cert = self.getCertificate("Harness", "SAS")
          self.SAS_harness_expired_Cert = self.getCertificate("Harness_Expired", "SAS")
          self.SAS_harness_unknown_Cert = self.getCertificate("Harness_Unknown", "SAS")
          self.SAS_harness_revoked_Cert = self.getCertificate("Harness_Revoked", "SAS")
          self.revokeCerticate(self.SAS_harness_revoked_Cert, self.SAS_CA)
          self.CPI_Cert = self.getCertificate("CPI", "CPI")

     def setUUTCertificate(self):
          UUT_Type = self.certData['customerType']
          self.UUT_Cert = self.getCertificate(UUT_Type, UUT_Type)
          
     def revokeCerticate(self, revokeCert = certificateAuthorityStructure(), revokeCA = certificateAuthorityStructure()):
          self.setCRLprefile(str(self.rawCertPath) + '\\etc\\pki\\CA')
          config = self.getCRLConfig({'revokeCert': revokeCA.certData['cert']}) 
          revokeCA.initCRL(config)
          revokeCA.revokeCertificate(config)

     def copySAScertificate(self):
          self.setToRawCertPath()
          certName = self.SAS_harness_Cert.certData['cert']
          keyName  = self.SAS_harness_Cert.certData['key']
          
          # root
          self.copyFile(self.Root_CA.certData['cert'], self.outputHarnessCertPath + "\\" + self.Root_CA.certData['cert'])
          
          # SAS certificate
          self.copyChainFile(self.outputHarnessCertPath + "\\SCS1\\" + certName, self.SAS_harness_Cert.certData['cert'], self.SAS_CA.certData['cert'])
          self.copyChainFile(self.outputHarnessCertPath + "\\SCS2\\" + certName, self.SAS_harness_revoked_Cert.certData['cert'], self.SAS_CA.certData['cert'])
          self.copyChainFile(self.outputHarnessCertPath + "\\SCS3\\" + certName, self.SAS_harness_expired_Cert.certData['cert'], self.SAS_CA.certData['cert'])
          self.copyChainFile(self.outputHarnessCertPath + "\\SCS4\\" + certName, self.SAS_harness_unknown_Cert.certData['cert'], self.SAS_CA.certData['cert'])
          self.copyChainFile(self.outputHarnessCertPath + "\\SCS5\\" + certName, self.SAS_harness_Cert.certData['cert'], self.SAS_CA.certData['cert'])
          self.copyFile(self.SAS_harness_Cert.certData['key'], self.outputHarnessCertPath + "\\SCS1\\" + keyName)
          self.copyFile(self.SAS_harness_revoked_Cert.certData['key'], self.outputHarnessCertPath + "\\SCS2\\" + keyName)
          self.copyFile(self.SAS_harness_expired_Cert.certData['key'], self.outputHarnessCertPath + "\\SCS3\\" + keyName)
          self.copyFile(self.SAS_harness_unknown_Cert.certData['key'], self.outputHarnessCertPath + "\\SCS4\\" + keyName)
          self.copyFile(self.SAS_harness_Cert.certData['key'], self.outputHarnessCertPath + "\\SCS5\\" + keyName)

     def copyUUTcertificate(self):
          self.setToRawCertPath()

          self.copyChainFile(self.outputUUTCertPath + '\\uutCertificate.pem', self.UUT_Cert.certData['cert'], self.UUT_CA.certData['cert'])
          self.copyChainFile(self.outputUUTCertPath + '\\CA_Bundle.pem', self.SAS_CA.certData['cert'], self.Root_CA.certData['cert'])
          self.copyFile(self.Root_CA.certData['cert'], self.outputUUTCertPath + '\\root.pem')
          self.copyFile(self.UUT_CA.certData['cert'], self.outputUUTCertPath + '\\uutCA.pem')
          self.copyFile(self.certNameConfig['CRL']['servercrl'], self.outputUUTCertPath + '\\servercrl.crl')


     def getCertificateAuthority(self, name, parentCA):
          os.chdir(self.rawCertPath)
          CA_config = self.getCertificateAuthorityConfig(name, parentCA)
          CA_structure = certificateAuthorityStructure(CA_config)
          return self.generateCertificate(CA_structure)

     def getCertificate(self, name, parentCA):
          os.chdir(self.rawCertPath)
          Cert_config = self.getCertificateConfig(name, parentCA)
          Cert_structure = certificateAuthorityStructure(Cert_config)
          return self.generateCertificate(Cert_structure)

     def getCertificateAuthorityConfig(self, name, parentCA = ""):
          config = collections.defaultdict(str)
          config.update({'configFile': self.configFile})
          config.update(self.certNameConfig["CA_Default"])
          config.update(self.certNameConfig[name + "_CA"])
          if name != "Root":
               config['parentCert'] = self.certNameConfig[parentCA + "_CA"]['cert']
               config['parentKey'] = self.certNameConfig[parentCA + "_CA"]['key']
          return config

     def getCertificateConfig(self, name, parentCA):
          config = collections.defaultdict(str)
          config.update({'configFile': self.configFile})
          config.update(self.certNameConfig["CertificateDefault"])
          config.update(self.certNameConfig[name + "_Certificate"])
          config['parentCert'] = self.certNameConfig[parentCA + "_CA"]['cert']
          config['parentKey']  = self.certNameConfig[parentCA + "_CA"]['key']

          # if there is uut type (cbsd or dp)
          if name == self.certData['customerType']: config['theTypeOfUUT'] = True

          return config

     def generateCertificate(self, Cert = certificateAuthorityStructure()):
          if Cert.certData['theTypeOfUUT'] == True:
               CustomerFile = self.certData['customerFile']
               noCustomerFile = ''
               isFileKey = re.search(r'.key$', CustomerFile, 0)
               isFileCsr = re.search(r'.csr$', CustomerFile, 0)
               print str(CustomerFile) + '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
               if CustomerFile == noCustomerFile:
                    Cert.certData['commonName'] = self.certData['fccId'] + ':' + self.certData['sn']
                    Cert.setKey()
                    Cert.setCsr()
                    Cert.setCert()

               else:
                    if isFileKey: 
                         Cert.certData['key'] = CustomerFile
                         Cert.setCsr()
                         Cert.setCert()

                    elif isFileCsr:
                         Cert.certData['csr'] = CustomerFile
                         Cert.setCert()
          else :
               Cert.setKey()
               Cert.setCsr()
               Cert.setCert()

          return Cert

     def setBrokenCertificate(self):
          pass
          
     def setCRLprefile(self, path):
          file = open(path + "/index.txt", "w")
          file.close()
          file = open(path + "/crlnumber", "w")
          file.write("01")
          file.close()

     def getCRLConfig(self, revokedCertConfig):
          config = collections.defaultdict(str)
          config.update(revokedCertConfig)
          config.update(self.certNameConfig["CRL"])
          return config

     def copyFile(self, sourceFile, targetFile):
          subprocess.call('COPY '+ sourceFile + ' ' + targetFile, shell = True)
          

     def copyChainFile(self, filename, cert1, cert2):
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

class certGeneratorInterface(object):

     def __init__(self):
          self.rootPath = str(os.path.dirname(os.path.dirname(__file__)))
          self.customerFile = ''
          self.fccId = ''
          self.sn = ''
     
     def userTypeIn(self):
          typeIn = raw_input('>> ')
          if typeIn == 'quit':
               sys.exit()
          else:
               return typeIn

     def isConfigExist(self):
          isConfigExist = False
          with open(self.rootPath + '\\config\\cert.json', 'r') as json_file:
               isConfigExist =  True
          return isConfigExist

     def menuQuestion(self):
          print '----------------------------'
          print u' 請選擇...'
          print u' (1) CBSD'
          print u' (2) CBSD with Domain Proxy'
          print u' (quit) 離開程式'
          print '----------------------------'

          userchoice = self.userTypeIn()
          if userchoice == '1':
               self.uutType = 'CBSD'
               return True
          elif userchoice == '2':
               self.uutType = 'DP'
               return True
          else :
               return False

     def customerFileExistQuestion(self):
          print u'客戶有無提供憑證相關檔案(Y/N)?'
          return self.userTypeIn()

     def customerFileNameQuestion(self):
          os.chdir(self.rootPath + '\\customerfile')
          print u'請輸入檔名( XXX.csr / XXX.key )'
          for name in glob.glob('*'): print name
          return self.userTypeIn()

     def customerCommonNameQuestion(self):
          print(u'請輸入 UUT FCC ID')
          self.fccId = self.userTypeIn()
          print(u'請輸入 UUT Serial Number')
          self.sn = self.userTypeIn()

     def certificateFolderName(self):
          print(u'請輸入 Certificate 資料夾名稱(預設certificates)')
          self.folderName = self.userTypeIn()
          self.folderName = self.folderName.strip()

     def certGenerate(self):
          config = {'customerType': self.uutType, 'outputDirName': self.folderName}
          config.update({'fccId': self.fccId, 'sn': self.sn})
          if self.customerFile != '': config.update({'customerFile': self.rootPath + '/customerfile/' + self.customerFile})
          generator = certGeneratorModel(config)
          generator.setConfig()
          generator.setRootCA()
          generator.setCertificateAuthority()
          generator.setCertificate()
          generator.setUUTCertificate()

