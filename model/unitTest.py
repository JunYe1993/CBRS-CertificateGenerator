import os
import unittest
from certGenerator import certStructure
from certGenerator import certificateAuthorityStructure
from certGenerator import certGeneratorModel

class Test_certStructure(unittest.TestCase):
     
     def test_init_1(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          testclass = certStructure(spec)
          
          # Act
          result = testclass.certData
          expect = spec

          # Assert
          self.assertEqual(result, expect)

     def test_init_2(self):
          
          # Arrange 
          testclass = certStructure()
          
          # Act
          result = testclass.certData
          expect = {"outputDirName":"certificates"}

          # Assert
          self.assertEqual(result, expect)

class Test_certificateAuthorityStructure(unittest.TestCase):

     def setUp(self):
          self.testclass = certificateAuthorityStructure()
     
     def test_init_1(self):
          
          # Arrange 
          testclass = certificateAuthorityStructure()
          
          # Act
          result = testclass.certData['customerType']
          expect = "UUT"

          # Assert
          self.assertEqual(result, expect)

     def test_getOpensslKeyCmd(self):

          pass

class Test_certGeneratorModel(unittest.TestCase):
     
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

if __name__ == '__main__':
     unittest.main()

