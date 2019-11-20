# -*- coding: UTF-8 -*-
import sys, os
import re
import json
import subprocess
import glob 

class Checker(object):

     def __init__(self):
          self.certfile = ''
          self.fccid = ''
          self.sn = ''

     def userTypeIn(self):
          typeIn = raw_input('>> ')
          if typeIn == 'quit':
               sys.exit()
          else:
               return typeIn

     def funcQuestion(self):
          # subprocess.call('cls', shell=True)
          print('----------------------------')
          print(u' 請選擇...')
          print(u' (1) 重新產生一組憑證')
          print(u' (2) 用已有憑證 產生 UUT 憑證')
          print(u' (quit) 離開程式')
          print('----------------------------')
          return self.userTypeIn()
     
     def findConfig(self):
          homepath = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
          os.chdir(str(homepath))
          with open(str(homepath)+'\\config\\cert.json', 'r') as json_file:  
               data = json.load(json_file)
          if os.path.isfile(str(homepath) + '/config/' + data['ConfigFile']['config']): 
               return True
          else:
               print(u'找不到'+data['ConfigFile']['config']+u', 程式結束!!')
               return False

     def checkCertificateMap(self):
          print(u'客戶有無提供憑證相關檔案(Y/N)?')
          userAnswer = self.userTypeIn()
          if userAnswer == 'Y':
               self.checkCustomerCertfile()
          elif userAnswer == 'N':
               self.checkUUTfccid()
          else:
               print(u'輸入有誤, 請再輸入一次')
               self.checkCertificateMap()
          return

     def checkCustomerCertfile(self):
          print(u'請輸入檔名( XXX.csr / XXX.key )')
          for name in glob.glob('customerfile/*'):
               print name
          filename = self.userTypeIn()
          if re.search(r'.key$', filename, 0):
               self.certfile = filename
               self.checkUUTfccid()
          else:
               if re.search(r'.csr$', filename, 0):
                    self.certfile = filename
               else:
                    print(u'certfile 有誤, 請再輸入一次')
                    self.checkCustomerCertfile()
          return
     
     def checkUUTfccid(self):
          print(u'請輸入 UUT FCC ID')
          self.fccid = self.userTypeIn()
          print(u'請輸入 UUT Serial Number')
          self.sn = self.userTypeIn()
     