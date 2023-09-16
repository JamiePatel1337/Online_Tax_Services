  # Online_Tax_Services
  VAT MTD API wrapper in Python3

 > Install pre-requisites:

 - sudo pip3 install -r requirements.txt

 > Operation:

 - sudo ./main.py -i : install
 - ./main.py -g : generate new OTP secret
 - ./main.py : login
    > check : check vat no.
    > list : list all clients
    > create : create new client
    > select : select client
    > retrieve : retrieve returns/obligations
    > return : complete and send vat return
    > view : view return
    > liability : view unpaid bills
    > payments : view payments
    > exit : exit app

 > To generate TOTP from Python use:

 - pyotp.TOTP('BASE32SECRET').now()
