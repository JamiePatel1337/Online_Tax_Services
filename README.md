
 > Changelog [V0-0-7]:

 - updated check VAT no. call for application restricted instead of open access
 - new config field ['LOGIN_INFO']['ACCESS'] for access token
 - updated CheckVatNumber with bearer token header
 - added v2.0 accept header
 - added RequestClientToken for client_credentials OAuth2 flow
 - updated CheckOtp with call to RequestClientToken on login
 - added logout after timeout feature
 - new config ['APP_CONFIG']['TIMEOUT'] in seconds
 - new class property activity_timer
 - new class methods StartTimer and CheckTimeout
 - tested on Linux Mint (Ubuntu) 21.1 - Mate desktop

 > Install pre-requisites:

 - sudo pip3 install -r requirements.txt

 > Operation:

 - sudo ./main.py -i : install
 - ./main.py -g : generate new OTP secret
 - ./main.py -p : change user password
 - ./main.py : login
    > check : check vat no.
    > list : list all clients
    > create : create new client
    > select : select client
    > retrieve : retrieve returns/obligations
    > return : complete and send vat return
    > view : view return
    > save : save return to csv
    > liability : view unpaid bills
    > payments : view payments
    > exit : exit app

 > To generate TOTP from Python use:

 - pyotp.TOTP('BASE32SECRET').now()
