import os
import collections
import subprocess

class certStructure(object):

     def __init__(self, data = {}):
          self.val = collections.defaultdict(str)
          self.val.update(data)
          if self.val['outputDirName'] == '':
               self.val['outputDirName'] = 'certificates'

     def isCertFile(self):
          return os.path.isfile(self.val['fileName'])

     def isDirExist(self):
          return os.path.isdir(self.rootPath)

class certGenerator(certStructure):

     def __init__(self, data = {}):
          self.certData = certStructure(data)
          self.rootPath = str(os.path.dirname(os.path.dirname(__file__))) + '\\' + self.certData.val['outputDirName']
          self.rawCertPath = self.rootPath + '\\OriginalCerts'
          self.outputUUTCertPath = self.rootPath + '\\ManagedCerts\\UUT'
          self.outputHarnessCertPath = self.rootPath + '\\ManagedCerts\\SAS-Test-Harness'
          self.makeDir()
          
     def makeDir(self):
          # remove dir has the same name
          subprocess.call('rmdir '+str(self.rootPath)+' /s /q', shell = True)

          subprocess.call('mkdir '+str(self.outputUUTCertPath), shell = True)
          subprocess.call('mkdir '+str(self.outputHarnessCertPath) + '\\SCS1', shell = True)
          subprocess.call('mkdir '+str(self.outputHarnessCertPath) + '\\SCS2', shell = True)
          subprocess.call('mkdir '+str(self.outputHarnessCertPath) + '\\SCS3', shell = True)
          subprocess.call('mkdir '+str(self.outputHarnessCertPath) + '\\SCS4', shell = True)
          subprocess.call('mkdir '+str(self.outputHarnessCertPath) + '\\SCS5', shell = True)

          # to work with config/opensslcbrs1.cnf
          subprocess.call('mkdir '+str(self.rawCertPath) + '\\etc\\pki\\CA', shell = True)

     
