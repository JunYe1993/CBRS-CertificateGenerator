import os
import unittest
import subprocess
import json
from certGenerator import certificateAuthorityStructure
from certGenerator import certGeneratorModel

"""
class Test_certificateAuthorityStructure(unittest.TestCase):

     def setUp(self):
          self.testclass = certificateAuthorityStructure()

          self.homePath = str(os.path.dirname(os.path.dirname(__file__))) + '/testfolder'
          self.homePath = os.path.abspath(self.homePath)
          self.configFile = str(os.path.dirname(os.path.dirname(__file__))) + '/config/opensslcbrs1.cnf' 

          subprocess.call('mkdir '+ self.homePath, shell = True)
          os.chdir(self.homePath)      
     
     def tearDown(self):
          self.testclass = None
          os.chdir(str(os.path.dirname(__file__)))
          subprocess.call('rmdir ' + self.homePath + ' /s /q', shell = True)
     
     def test_setKey_Normal(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\123.key')
          expect = True

          # Assert
          self.assertEqual(result, expect)
     
     def test_setKey_NoConfig(self):
          # Arrange 
          config = {}
          self.testclass.setKey(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\123.key')
          expect = False

          # Assert
          self.assertEqual(result, expect)
     
     def test_setRootCert_Normal(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/123.key', 'cert': 'root.cert', 'validity': '1'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\root.cert')
          expect = True

          # Assert
          self.assertEqual(result, expect)
     
     def test_setRootCert_NoKeyFile(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/1234.key', 'cert': 'root.cert', 'validity': '1'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\root.cert')
          expect = False

          # Assert
          self.assertEqual(result, expect) 
     
     def test_setRootCert_WrongConfig(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/123.key', 'cert': 'root.cert', 'validity': '1'}
          config.update({'countryName': 'Taiwan', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\root.cert')
          expect = False

          # Assert
          self.assertEqual(result, expect) 

     def test_setCsr_Normal(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/123.key', 'csr': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\mycsr.csr')
          expect = True

          # Assert
          self.assertEqual(result, expect)
     
     def test_setCsr_NoCsrFile(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/1234.key', 'csr': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\mycsr.csr')
          expect = False

          # Assert
          self.assertEqual(result, expect)
     
     def test_setCsr_WrongConfig(self):
          # Arrange 
          config = {'key': '123.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/1234.key', 'csres': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          
          # Act
          result = os.path.isfile(self.homePath + '\\mycsr.csr')
          expect = False

          # Assert
          self.assertEqual(result, expect)
     
     def test_setCert_Normal(self):
          # Arrange 
          config = {'key': 'root.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/root.key', 'cert': 'root.pem', 'validity': '100'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)

          config = {'key': 'mykey.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/mykey.key', 'csr': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          config = {'csr': 'mycsr.csr', 'parentCert': 'root.pem', 'parentKey': 'root.key', 'cert': 'mycert.pem', 'validity': '100', 'extensions': 'cbrs_sas_ca'}
          config.update({'configFile': self.configFile})
          self.testclass.setCert(config)

          # Act
          result = os.path.isfile(self.homePath + '\\mycert.pem')
          expect = True

          # Assert
          self.assertEqual(result, expect)
     
     def test_setCert_NoCertFile(self):
          # Arrange 
          config = {'key': 'root.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/root.key', 'cert': 'root.pem', 'validity': '100'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)

          config = {'key': 'mykey.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/mykey.key', 'csr': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          config = {}
          self.testclass.setCert(config)

          # Act
          result = os.path.isfile(self.homePath + '\\mycert.pem')
          expect = False

          # Assert
          self.assertEqual(result, expect)

     def test_setCert_WrongValidity(self):
          # Arrange 
          config = {'key': 'root.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/root.key', 'cert': 'root.pem', 'validity': '100'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA ROOT CA9001', 'commonName': 'Sporton RSA Root CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setRootCert(config)

          config = {'key': 'mykey.key', 'keysize': '4096'}
          self.testclass.setKey(config)
          config = {'key': str(self.homePath) + '/mykey.key', 'csr': 'mycsr.csr'}
          config.update({'countryName': 'TW', 'organizationName': 'Sporton', 'organizationUnitName': 'RSA SAS Provider CA9001', 'commonName': 'Sporton RSA SAS Provider CA'})
          config.update({'configFile': self.configFile})
          self.testclass.setCsr(config)
          config = {'csr': 'mycsr.csr', 'parentCert': 'root.pem', 'parentKey': 'root.key', 'cert': 'mycert.pem', 'validity': '0', 'extensions': 'cbrs_sas_ca'}
          config.update({'configFile': self.configFile})
          self.testclass.setCert(config)

          # Act
          result = os.path.isfile(self.homePath + '\\mycert.pem')
          expect = False

          # Assert
          self.assertEqual(result, expect)
"""
class Test_certGeneratorModel(unittest.TestCase):

     def setUp(self):
          self.rootPath = str(os.path.dirname(os.path.dirname(__file__)))
     
     def test_init(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          testclass = certGeneratorModel(spec)
          
          # Act
          result = testclass.rootPath
          expect = os.path.abspath(str(os.path.dirname(os.path.dirname(__file__))) + '\\qwert')
          testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)

     def test_makeDir_1(self):
          
          # Arrange 
          testclass = certGeneratorModel()
          
          # Act
          result = os.path.isdir(str(os.path.dirname(os.path.dirname(__file__))) + '\\certificates')
          expect = True
          testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)
     
     def test_makeDir_2(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          testclass = certGeneratorModel(spec)
          
          # Act
          result = os.path.isdir(str(os.path.dirname(os.path.dirname(__file__))) + '\\qwert')
          expect = True
          testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)

     def test_setConfig(self):
          
          # Arrange 
          testclass = certGeneratorModel()
          testclass.setConfig()
          
          # Act
          result = os.path.isfile(testclass.configFile)
          expect = True
          testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)
     """
     def test_setRootCA(self):

          # Arrange 
          testclass = certGeneratorModel()
          testclass.setConfig()
          testclass.setRootCA()
          
          # Act
          result = os.path.isfile(testclass.configFile)
          expect = True
          # testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)
     """
     def test_setSASCA(self):

          # Arrange 
          testclass = certGeneratorModel({'customerFile': self.rootPath + '/customerfile/cbsduutcsr.csr'})
          testclass.setConfig()
          testclass.setRootCA()
          testclass.setCertificateAuthority()
          testclass.setCertificate()
          
          # Act
          result = os.path.isfile(testclass.configFile)
          expect = True
          # testclass.removeDir()

          # Assert
          self.assertEqual(result, expect)

if __name__ == '__main__':
     unittest.main()

