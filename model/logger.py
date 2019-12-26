
class logger(object):

     def __init__(self, prefix = ''):
          self.prefix = prefix

     def setScreenPrint(self, message):
          print self.prefix, message