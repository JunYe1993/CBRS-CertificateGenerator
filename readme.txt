
     安裝
          1. Python 2.7.x
          2. Openssl
          
     執行
          1. 若客戶有將給予憑證相關檔案，請把檔案放入 customerfile
          2. 執行 controller/certGenerator.py

======================================================================

uutCertificate.pem =    ------------------
                          uutCertificate
                        ------------------
                        ------------------
                              uutCA
                        ------------------
						
						

uutCA.pem = 	        ------------------
                              uutCA
                        ------------------
						
						

rootCA.pem =            ------------------
                              rootCA
                        ------------------



CA_Bundle =             ------------------
                              SAS_CA
                        ------------------
                        ------------------
                              rootCA
                        ------------------
