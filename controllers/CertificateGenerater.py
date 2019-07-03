# -*- coding: UTF-8 -*-
import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from model.CertChecker import Checker
from model.CertGenerater import Generater

CustomerParameters = Checker()
while CustomerParameters.findConfig():

     userchoice = CustomerParameters.funcQuestion()
     
     if userchoice == '1':
          CustomerParameters.checkCertificateMap()
          myCert = Generater(CustomerParameters.certfile, CustomerParameters.fccid, CustomerParameters.sn)
          if myCert.checkFiles():
               myCert.createFolder()
               myCert.createCerts()
               myCert.createUUTcerts()

     elif userchoice == '2':
          CustomerParameters.checkCertificateMap()
          myCert = Generater(CustomerParameters.certfile, CustomerParameters.fccid, CustomerParameters.sn)
          if myCert.checkCustomerFiles():
               myCert.createUUTcerts()

          

