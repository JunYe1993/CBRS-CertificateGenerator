# -*- coding: UTF-8 -*-
import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from model.certGenerator import certGeneratorInterface
from model.certGenerator import certGeneratorModel

certShell = certGeneratorInterface()
while certShell.isConfigExist():
     
     backToMenu = False 
     userState = certShell.menuQuestion()
     
     while userState:

          customerFileExist = certShell.customerFileExistQuestion()
          customerFileExist = str.upper(customerFileExist)

          while customerFileExist == 'Y':

               customerFileName = certShell.customerFileNameQuestion()

               if os.path.isfile(customerFileName):
                    certShell.customerFile = customerFileName
                    certShell.certificateFolderName()
                    certShell.certGenerate()
                    userState = backToMenu
                    break

          while customerFileExist == 'N':

               certShell.customerCommonNameQuestion()
               certShell.certificateFolderName()
               certShell.certGenerate()
               userState = backToMenu
               break




