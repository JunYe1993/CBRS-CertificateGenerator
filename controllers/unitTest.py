# -*- coding: UTF-8 -*-
import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from model.CertChecker import Checker
from model.CertGenerater import Generater

print('certfile : ')
certfile = Checker().userTypeIn()
print('fccid : ')
fccid    = Checker().userTypeIn()
print('sn : ')
sn       = Checker().userTypeIn()

myCert = Generater( certfile, fccid, sn)
myCert.createFolder()
# myCert.createCerts()
myCert.createUUTcerts()


