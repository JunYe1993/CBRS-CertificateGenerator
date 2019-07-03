# -*- coding: UTF-8 -*-
import sys, os
import subprocess
import json
import re
from model.CertChecker import Checker

class Generater(object):
     
     def __init__(self, certfile, fccid, sn):

          self.homepath = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
          self.certfile = certfile
          self.fccid = fccid
          self.sn = sn

     def createFolder(self):

          print('removing path...')
          subprocess.call('rmdir '+str(self.homepath)+'\\certificates /s /q', shell = True)
          
          print('adding path...')
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\UUT', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\SCS1', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\SCS2', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\SCS3', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\SCS4', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\SCS5', shell = True)
          subprocess.call('mkdir '+str(self.homepath)+'\\certificates\\OringinalCerts\\etc\\pki\\CA', shell = True)

     def checkFiles(self):

          os.chdir(str(self.homepath)+'\\customerfile')
          if self.certfile != '' and not os.path.isfile(self.certfile):
               print(u"找不到客戶憑證檔案 "+self.certfile)
               return False
          
          os.chdir(str(self.homepath))
          if os.path.isdir('certificates'):
               print(u'已存在certificates, 是否覆蓋(Y/N)?')
               userAnwer = Checker().userTypeIn()
               if userAnwer == 'Y':
                    return True
               elif userAnwer == 'N':
                    return False
               else:
                    return self.checkFiles()
                    
          return True

     def checkCustomerFiles(self):

          os.chdir(str(self.homepath)+'\\customerfile')
          if self.certfile != '' and not os.path.isfile(self.certfile):
               print(u"找不到客戶憑證檔案 "+self.certfile)
               return False

          os.chdir(str(self.homepath))
          if not os.path.isdir('certificates'):
               print(u'不存在已有certificates')
               return False

          return True

     def createCerts(self):
          with open(str(self.homepath)+'\\config\\cert.json', 'r') as json_file:  
               data = json.load(json_file)
          config = str(self.homepath)+'\\config\\'+data['ConfigFile']['config']
          crlpath = str(self.homepath)+'\\certificates\\OringinalCerts\\'+data['ConfigFile']['crlpath']
          os.chdir(str(self.homepath)+'\\certificates\\OringinalCerts')
          

          #### Root certificate

          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['Root_CA']['organization']+'/OU='+data['Root_CA']['OU']+'/CN='+data['Root_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['Root_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-x509','-key', data['Root_CA']['key'],'-out', data['Root_CA']['cert'],'-days', data['CA_Default']['validity'],'-subj', certinformation,'-config', config])
          

          #### Other CA certificate

          ## SAS CA
          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['CA_Default']['organization']+'/OU='+data['SAS_CA']['OU']+'/CN='+data['SAS_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['SAS_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['SAS_CA']['key'],'-out', data['SAS_CA']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['SAS_CA']['csr'],'-CA', data['Root_CA']['cert'],'-CAkey', data['Root_CA']['key'],'-CAcreateserial','-out', data['SAS_CA']['cert'],'-days', data['CA_Default']['validity'],'-sha384','-extfile', config, '-extensions', 'cbrs_sas_ca'])

          ## CBSD CA
          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['CA_Default']['organization']+'/OU='+data['CBSD_CA']['OU']+'/CN='+data['CBSD_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['CBSD_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['CBSD_CA']['key'],'-out', data['CBSD_CA']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['CBSD_CA']['csr'],'-CA', data['Root_CA']['cert'],'-CAkey', data['Root_CA']['key'],'-CAcreateserial','-out', data['CBSD_CA']['cert'],'-days', data['CA_Default']['validity'],'-sha384','-extfile', config, '-extensions', 'cbrs_cbsd_mfr_ca'])

          ## DP CA
          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['CA_Default']['organization']+'/OU='+data['DP_CA']['OU']+'/CN='+data['DP_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['DP_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['DP_CA']['key'],'-out', data['DP_CA']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['DP_CA']['csr'],'-CA', data['Root_CA']['cert'],'-CAkey', data['Root_CA']['key'],'-CAcreateserial','-out', data['DP_CA']['cert'],'-days', data['CA_Default']['validity'],'-sha384','-extfile', config, '-extensions', 'cbrs_domain_proxy_ca'])

          ## SAS Unknown CA
          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['CA_Default']['organization']+'/OU='+data['SAS_Unknown_CA']['OU']+'/CN='+data['SAS_Unknown_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['SAS_Unknown_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['SAS_Unknown_CA']['key'],'-out', data['SAS_Unknown_CA']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['SAS_Unknown_CA']['csr'],'-CA', data['Root_CA']['cert'],'-CAkey', data['Root_CA']['key'],'-CAcreateserial','-out', data['SAS_Unknown_CA']['cert'],'-days', data['CA_Default']['validity'],'-sha384','-extfile', config, '-extensions', 'cbrs_sas_ca'])
          
          ## CPI CA
          certinformation = '/C='+data['CA_Default']['country']+'/O='+data['CPI_CA']['organization']+'/OU='+data['CPI_CA']['OU']+'/CN='+data['CPI_CA']['CN']
          subprocess.call(['openssl','genrsa','-out', data['CPI_CA']['key'], data['CA_Default']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['CPI_CA']['key'],'-out', data['CPI_CA']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['CPI_CA']['csr'],'-CA', data['Root_CA']['cert'],'-CAkey', data['Root_CA']['key'],'-CAcreateserial','-out', data['CPI_CA']['cert'],'-days', data['CA_Default']['validity'],'-sha384','-extfile', config, '-extensions', 'professional_installer_ca'])
          

          #### SAS Test Harness Certificate
     
          ## Harness Certificate
          certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['Harness_Certificate']['organization']+'/OU='+data['CertificateDefault']['OU']+'/CN='+data['Harness_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', data['Harness_Certificate']['key'], data['CertificateDefault']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['Harness_Certificate']['key'],'-out', data['Harness_Certificate']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['Harness_Certificate']['csr'],'-CA', data['SAS_CA']['cert'],'-CAkey', data['SAS_CA']['key'],'-CAcreateserial','-out', data['Harness_Certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'sas_cert'])
          
          ## Harness Unknown Certificate
          certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['CertificateDefault']['OU']+'/CN='+data['Harness_Unknown_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', data['Harness_Unknown_Certificate']['key'], data['CertificateDefault']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['Harness_Unknown_Certificate']['key'],'-out', data['Harness_Unknown_Certificate']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['Harness_Unknown_Certificate']['csr'],'-CA', data['SAS_Unknown_CA']['cert'],'-CAkey', data['SAS_Unknown_CA']['key'],'-CAcreateserial','-out', data['Harness_Unknown_Certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'sas_cert'])

          ## Harness Expired Certificate
          certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['CertificateDefault']['OU']+'/CN='+data['Harness_Expire_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', data['Harness_Expire_Certificate']['key'], data['CertificateDefault']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['Harness_Expire_Certificate']['key'],'-out', data['Harness_Expire_Certificate']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['Harness_Expire_Certificate']['csr'],'-CA', data['SAS_CA']['cert'],'-CAkey', data['SAS_CA']['key'],'-CAcreateserial','-out', data['Harness_Expire_Certificate']['cert'],'-days', data['Harness_Expire_Certificate']['validity'],'-sha256','-extfile', config, '-extensions', 'sas_cert'])

          ## Harness Revoke Certificate
          certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['CertificateDefault']['OU']+'/CN='+data['Harness_Revoke_Certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', data['Harness_Revoke_Certificate']['key'], data['CertificateDefault']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['Harness_Revoke_Certificate']['key'],'-out', data['Harness_Revoke_Certificate']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['Harness_Revoke_Certificate']['csr'],'-CA', data['SAS_CA']['cert'],'-CAkey', data['SAS_CA']['key'],'-CAcreateserial','-out', data['Harness_Revoke_Certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'sas_cert_with_crl'])

          ## Harness Broken Certificate
          self.createBrokenCertificate(data['Harness_Certificate']['cert'], data['Harness_Broken_Certificate']['cert'])


          #### the unified PKI chain PEM file containing sub-CA

          self.createCertChain(data['Harness_Certificate']['cert'], data['SAS_CA']['cert'])
          self.createCertChain(data['Harness_Unknown_Certificate']['cert'], data['SAS_CA']['cert'])
          self.createCertChain(data['Harness_Expire_Certificate']['cert'], data['SAS_CA']['cert'])
          self.createCertChain(data['Harness_Revoke_Certificate']['cert'], data['SAS_CA']['cert'])
          self.createCertChain(data['Harness_Broken_Certificate']['cert'], data['SAS_CA']['cert'])


          #### CPI Certificate

          certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['CPI_certificate']['OU']+'/CN='+data['CPI_certificate']['CN']
          subprocess.call(['openssl','genrsa','-out', data['CPI_certificate']['key'], data['CertificateDefault']['keysize']])
          subprocess.call(['openssl','req','-new','-key', data['CPI_certificate']['key'],'-out', data['CPI_certificate']['csr'],'-subj', certinformation,'-config', config])
          subprocess.call(['openssl','x509','-req','-in', data['CPI_certificate']['csr'],'-CA', data['CPI_CA']['cert'],'-CAkey', data['CPI_CA']['key'],'-CAcreateserial','-out', data['CPI_certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'cpi_cert'])

          #### Certificate Revocation List (CRL file)

          ## create pre-file for CRL
          self.createCRLprefile(crlpath)

          ## create CRL
          subprocess.call(['openssl','ca','-config', config,'-gencrl','-keyfile', data['SAS_CA']['key'],'-cert', data['SAS_CA']['cert'],'-out', data['CRL']['emptycrl']])
          subprocess.call(['openssl','ca','-revoke', data['Harness_Revoke_Certificate']['cert'],'-config', config,'-keyfile', data['SAS_CA']['key'],'-cert', data['SAS_CA']['cert']])


          #### Copy

          curpath = str(self.homepath)+'\\certificates\\OringinalCerts\\'
          targetpath = ' '+str(self.homepath)+'\\certificates\\ManagedCerts\\SAS-Test-Harnss\\'
          subprocess.call('COPY '+curpath+ data['Root_CA']['cert'] + targetpath + data['Root_CA']['cert'], shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Certificate']['key']  +targetpath+ 'SCS1\\' + data['Harness_Certificate']['key'],   shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Certificate']['cert'] +targetpath+ 'SCS1\\' + data['Harness_Certificate']['cert'],  shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Unknown_Certificate']['key']  +targetpath+ 'SCS4\\' + data['Harness_Certificate']['key'],   shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Unknown_Certificate']['cert'] +targetpath+ 'SCS4\\' + data['Harness_Certificate']['cert'],  shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Expire_Certificate']['key']   +targetpath+ 'SCS3\\' + data['Harness_Certificate']['key'],   shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Expire_Certificate']['cert']  +targetpath+ 'SCS3\\' + data['Harness_Certificate']['cert'],  shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Revoke_Certificate']['key']   +targetpath+ 'SCS2\\' + data['Harness_Certificate']['key'],   shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Revoke_Certificate']['cert']  +targetpath+ 'SCS2\\' + data['Harness_Certificate']['cert'],  shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Broken_Certificate']['key']   +targetpath+ 'SCS5\\' + data['Harness_Certificate']['key'],   shell = True)
          subprocess.call('COPY '+curpath+ data['Harness_Broken_Certificate']['cert']  +targetpath+ 'SCS5\\' + data['Harness_Certificate']['cert'],  shell = True)

          os.chdir(str(self.homepath))
     
     def createBrokenCertificate(self, orifile, brokefile):
          file_data = ""
          with open(orifile, "r") as f:
               for line in f:
                    if 'h' in line:
                         line = line.replace('h', 'a')
                    if 'H' in line:
                         line = line.replace('H', 'b')
                    file_data += line

          with open(brokefile , "w") as f:
               f.write(file_data)

     def createCertChain(self, cert, ca):
          file_data = ""
          with open(ca, "r") as f:
               for line in f:
                    file_data += line
          
          with open(cert , "a") as f:
               f.write(file_data)

     def createCRLprefile(self, path):
          file = open(path + "/index.txt", "w")
          file.close()
          file = open(path + "/crlnumber", "w")
          file.write("01")
          file.close()

     def createUUTcerts(self):
          customerfilepath = str(self.homepath)+'\\customerfile\\'
          with open(str(self.homepath)+'\\config\\cert.json', 'r') as json_file:  
               data = json.load(json_file)
          config = str(self.homepath)+'\\config\\'+data['ConfigFile']['config']
          os.chdir(str(self.homepath)+'\\certificates\\OringinalCerts')
          if self.certfile == '':
               certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['UUT_certificate']['OU']+'/CN='+self.fccid+':'+self.sn
               subprocess.call(['openssl','genrsa','-out', data['UUT_certificate']['key'], data['CertificateDefault']['keysize']])
               subprocess.call(['openssl','req','-new','-key', data['UUT_certificate']['key'],'-out', data['UUT_certificate']['csr'],'-subj', certinformation,'-config', config])
               subprocess.call(['openssl','x509','-req','-in', data['UUT_certificate']['csr'],'-CA', data['CBSD_CA']['cert'],'-CAkey', data['CBSD_CA']['key'],'-CAcreateserial','-out', data['UUT_certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'cbsd_cert'])
          elif re.search(r'.key$', self.certfile, 0):
               certinformation = '/C='+data['CertificateDefault']['country']+'/O='+data['CertificateDefault']['organization']+'/OU='+data['UUT_certificate']['OU']+'/CN='+self.fccid+':'+self.sn
               subprocess.call(['openssl','req','-new','-key', customerfilepath+self.certfile,'-out', data['UUT_certificate']['csr'],'-subj', certinformation,'-config', config])
               subprocess.call(['openssl','x509','-req','-in', data['UUT_certificate']['csr'],'-CA', data['CBSD_CA']['cert'],'-CAkey', data['CBSD_CA']['key'],'-CAcreateserial','-out', data['UUT_certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'cbsd_cert'])
          elif re.search(r'.csr$', self.certfile, 0):
               subprocess.call(['openssl','x509','-req','-in', customerfilepath+self.certfile,'-CA', data['CBSD_CA']['cert'],'-CAkey', data['CBSD_CA']['key'],'-CAcreateserial','-out', data['UUT_certificate']['cert'],'-days', data['CertificateDefault']['validity'],'-sha256','-extfile', config, '-extensions', 'cbsd_cert'])

          self.createCertChain(data['UUT_certificate']['cert'], data['CBSD_CA']['cert'])  

          curpath = str(self.homepath)+'\\certificates\\OringinalCerts\\'
          targetpath = ' '+str(self.homepath)+'\\certificates\\ManagedCerts\\UUT\\'
          subprocess.call('COPY '+curpath+ data['Root_CA']['cert'] + targetpath + data['Root_CA']['cert'], shell = True)
          subprocess.call('COPY '+curpath+ data['CBSD_CA']['cert']  +targetpath + data['CBSD_CA']['cert'],   shell = True)
          subprocess.call('COPY '+curpath+ data['UUT_certificate']['cert']  +targetpath + data['UUT_certificate']['cert'],   shell = True)

     
     

