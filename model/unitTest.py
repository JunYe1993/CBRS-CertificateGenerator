import os
import unittest
from certGenerator import certStructure
from certGenerator import certGenerator

class Test_certStructure(unittest.TestCase):
     
     def test_init_1(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          testclass = certStructure(spec)
          
          # Act
          result = testclass.val
          expect = spec

          # Assert
          self.assertEqual(result, expect)

     def test_init_2(self):
          
          # Arrange 
          testclass = certStructure()
          
          # Act
          result = testclass.val
          expect = {"outputDirName":"certificates"}

          # Assert
          self.assertEqual(result, expect)

class Test_certGenerator(unittest.TestCase):
     
     def test_init(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          testclass = certGenerator(spec)
          
          # Act
          result = testclass.rootPath
          expect = os.path.abspath(str(os.path.dirname(os.path.dirname(__file__))) + '\\qwert')

          # Assert
          self.assertEqual(result, expect)

     def test_makeDir_1(self):
          
          # Arrange 
          certGenerator()
          
          # Act
          result = os.path.isdir(str(os.path.dirname(os.path.dirname(__file__))) + '\\certificates')
          expect = True

          # Assert
          self.assertEqual(result, expect)
     
     def test_makeDir_2(self):
          
          # Arrange 
          spec = {"fccid": "123", "sn": "321", "outputDirName": "qwert"}
          certGenerator(spec)
          
          # Act
          result = os.path.isdir(str(os.path.dirname(os.path.dirname(__file__))) + '\\qwert')
          expect = True

          # Assert
          self.assertEqual(result, expect)

if __name__ == '__main__':
     unittest.main()

