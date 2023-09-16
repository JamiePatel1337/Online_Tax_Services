
import os
import sys
import json
import uuid
import pyotp
import ifcfg
import argparse
import requests
import datetime
import pyautogui
import webbrowser
import http.server
import socketserver

from hashlib import sha256
from urllib.parse import quote, urlparse, parse_qs

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

global AUTH_CODE
global AUTH_STATE

AUTH_CODE = ''
AUTH_STATE = ''

class RedirectParser(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):

        global AUTH_CODE
        global AUTH_STATE

        self.send_response(200)

        self.send_header("Content-type", "text/html")
        self.end_headers()

        query_components = parse_qs(urlparse(self.path).query)

        if 'code' not in query_components or 'state' not in query_components:
            return 1

        AUTH_CODE = query_components["code"][0]
        AUTH_STATE = query_components["state"][0]

        d = {"success": True}
        message = json.dumps(d)
        self.wfile.write(bytes(message, "utf8"))

        return 0

class OnlineTaxServices():

    run_mode = ''

    config_file = ''
    config = {}

    session = None
    response = None

    headers = {}

    client_index = None
    active_client = ''
    access_token = ''

    def __init__(self, config_file: str) -> None:

        self.run_mode = 'SHELL'

        self.config_file = config_file

        self.config = self.GetUserArgs()

    def GetUserArgs(self):

        if(len(sys.argv) > 2):
            print('Invalid usage! Exiting...')
            sys.exit(1)

        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--install", action='store_true', help=f"Install configuration")
        parser.add_argument("-g", "--generate", action='store_true', help=f"Generate new authenticator QR code")
        args = parser.parse_args()

        if args.install == True and args.generate == True:
            print('Invalid usage! Exiting...')
            sys.exit(1)
        
        if args.install == True:

            if os.geteuid() != 0:
                print('Run installer as root! Exiting...')
                sys.exit(1)

            if os.path.exists(self.config_file) == True:
                print('Config file already exists! Exiting...')
                sys.exit(1)

            self.run_mode = 'INSTALL'
            return {}

        if os.geteuid() == 0:
            print('Do not run interactive shell or generator as root! Exiting...')
            sys.exit(1)

        if os.path.exists(self.config_file) == False:
            print('Config file does not exist! Exiting...')
            sys.exit(1)
        name, ext =  os.path.splitext(self.config_file)
        if ext != '.json':
            print("Invalid config file! Exiting...")
            sys.exit(1)

        if args.generate == True:
            self.run_mode = 'GENERATE'
        
        with open(self.config_file, 'r') as cfg_file:
            return json.load(cfg_file)

    def SaveConfig(self, overwrite=False) -> None:
        if overwrite == False:
            with open(self.config_file, 'r') as cfg_file:
                cfg = json.load(cfg_file)
            with open(f"{self.config_file}.bk", 'w', encoding='utf-8') as f:
                f.write(json.dumps(cfg))
                os.system(f"chmod 600 {self.config_file}.bk")
                os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {self.config_file}.bk")
        with open(f"{self.config_file}", 'w', encoding='utf-8') as f:
            f.write(json.dumps(self.config))
        os.system(f"chmod 644 {self.config_file}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {self.config_file}")

    def EncodeString(self, string) -> str:
        return quote(string, safe='-=.')
    
    def CalculateHash(self, string: str) -> str:
        return sha256(string.encode('utf-8')).hexdigest()

    def GetClientIndex(self, string):
        for client in self.config['DATABASE_INFO']:
            for key, value in client.items():
                if key == 'CLIENT_ID' and value == string:
                    return self.config['DATABASE_INFO'].index(client)
        return None
    
    def GetReturnIndex(self, string):
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return None
        for v_return in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            for key, value in v_return.items():
                if key == 'PERIOD_KEY' and value == string:
                    return self.config['DATABASE_INFO'][self.client_index]['RETURNS'].index(v_return)
        return None

    def CheckOtp(self, otp) -> int:
        if otp == pyotp.TOTP(self.config['USER_INFO']['TOTP_SECRET']).now():
            
            ip_info = []
            mac_info = []
            
            for name, interface in ifcfg.interfaces().items():
                if interface['inet'] is not None:
                    ip_info.append(interface['inet'])
                if interface['ether'] is not None:
                    mac_info.append(interface['ether'])

            if len(ip_info) < 1 or len(mac_info) < 1:
                print('Check connection and try again! Exiting...')
                sys.exit(1)
            
            ip_str = ip_info[0]
            mac_str = self.EncodeString(mac_info[0])
            if len(ip_info) > 1:
                for ip in ip_info:
                    if ip_info.index(ip) != 0:
                        ip_str += ',' + ip
            if len(mac_info) > 1:
                for mac in mac_info:
                    if mac_info.index(mac) != 0:
                        mac_str += ',' + self.EncodeString(mac)

            date_time = datetime.datetime.now(datetime.timezone(datetime.timedelta()))
            zone = datetime.datetime.now(datetime.timezone(datetime.timedelta())).astimezone().tzinfo

            self.config['LOGIN_INFO'].update({"IP": str(ip_str)})
            self.config['LOGIN_INFO'].update({"TIME": f"{date_time.date()}T{date_time.strftime('%X')}.{date_time.microsecond // 1000}Z"})
            self.config['LOGIN_INFO'].update({"TZ": str(zone)})
            self.config['LOGIN_INFO'].update({"MAC": str(mac_str)})
            self.config['LOGIN_INFO'].update({"MFA": f"type={self.config['USER_INFO']['OTP_TYPE']}&timestamp={self.EncodeString(self.config['LOGIN_INFO']['TIME'])}&unique-reference={self.EncodeString(self.config['USER_INFO']['OTP_REFERENCE'])}"})

            term = os.get_terminal_size()
            self.config['AGENT_INFO']['SCREEN'].update({"W_WIDTH": ((term.columns * 16) + 30)})
            self.config['AGENT_INFO']['SCREEN'].update({"W_HEIGHT": ((term.lines * 35) + 31)})

            self.SaveConfig()

            return 0
        else:
            return -1

    def Install(self) -> int:

        if self.config != {}:
            print("Broken config! Exiting...")
            sys.exit(1)
        
        if os.geteuid() != 0:
            print('Run installer as root! Exiting...')
            sys.exit(1)

        c_ver = {}
        c_app = {}
        c_use = {}
        c_dev = {}
        c_scr = {}
        c_agn = {}

        #version control
        c_ver.update({"APP_NAME": "Online_Tax_Services"})
        c_ver.update({"APP_VERSION": "0.0.3"})

        #app info
        id = str(input("Enter HMRC Client ID: "))
        sec = str(input("Enter HMRC Client Secret: "))
        try:
            uri = int(input("Enter URI port: "))
        except Exception:
            print("Port must be int! Exiting...")
            sys.exit(1)
        if uri > 65535:
            print("Port must be < 65536! Exiting...")
            sys.exit(1)
        c_app.update({"BASE_URL": "https://test-api.service.hmrc.gov.uk/"})
        c_app.update({"CLIENT_ID": f"{id}"})
        c_app.update({"CLIENT_SECRET": f"{sec}"})
        c_app.update({"URI_PORT": uri})

        #user info
        user = str(input("Enter UserName: "))
        c_use.update({"USER_NAME": f"{user}"})
        c_use.update({"OTP_TYPE": "TOTP"})

        #device info
        domn = str(input("Enter Domain/Group: "))
        c_dev.update({"DOMAIN": f"{domn}"})
        c_dev.update({"CONNECTION_METHOD": "DESKTOP_APP_DIRECT"})
        c_dev.update({"DEVICE_ID": f"{str(uuid.uuid4())}"})
        c_dev.update({"LICENSE": self.CalculateHash(c_dev['DEVICE_ID'])})

        #screen info
        import tkinter
        root = tkinter.Tk()
        c_scr.update({"WIDTH": f"{root.winfo_screenwidth()}"})
        c_scr.update({"HEIGHT": f"{root.winfo_screenheight()}"})
        root.destroy
        c_scr.update({"SCALING": 1})
        c_scr.update({"COLOUR": 32})
        term = os.get_terminal_size()
        c_scr.update({"W_WIDTH": ((term.columns * 16) + 30)})
        c_scr.update({"W_HEIGHT": ((term.lines * 35) + 31)})
        #agent info
        import platform
        from dmidecode.decode import DMIDecode
        dmi = DMIDecode()
        c_agn.update({"SYSTEM": platform.system()})
        c_agn.update({"RELEASE": platform.release()})
        c_agn.update({"MANUFACTURER": dmi.manufacturer()})
        c_agn.update({"PRODUCT": dmi.model()})
        c_agn.update({"SCREEN": c_scr})

        self.config.update({"VERSION_INFO": c_ver})
        self.config.update({"APP_CONFIG": c_app})
        self.config.update({"USER_INFO": c_use})
        self.config.update({"DEVICE_INFO": c_dev})
        self.config.update({"AGENT_INFO": c_agn})
        self.config.update({"LOGIN_INFO": {}})
        self.config.update({"DATABASE_INFO": []})

        self.SaveConfig(overwrite=True)

        if self.GenerateSecret() != 0:
            print("TOTP generator failed! Exiting...")
            sys.exit(1)

        return 0

    def GenerateSecret(self) -> int:
        import qrcode
        self.config['USER_INFO'].update({"TOTP_SECRET": pyotp.random_base32()})
        self.config['USER_INFO'].update({"OTP_REFERENCE": self.CalculateHash(self.config['USER_INFO']['TOTP_SECRET'])})
        self.SaveConfig()
        auth = pyotp.TOTP(self.config['USER_INFO']['TOTP_SECRET']).provisioning_uri(name=self.config['USER_INFO']['USER_NAME'], issuer_name=self.config['VERSION_INFO']['APP_NAME'])
        file_name = './qrcode.png'
        qrcode.make(auth).save(file_name)
        os.system(f"chmod 644 {file_name}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {file_name}")
        return 0

    def PopulateHeaders(self):

        self.headers = {}
        self.headers.update({"Accept": "application/vnd.hmrc.1.0+json"})
        self.headers.update({"Gov-Client-Connection-Method": self.config['DEVICE_INFO']['CONNECTION_METHOD']})
        self.headers.update({"Gov-Client-Device-ID": self.config['DEVICE_INFO']['DEVICE_ID']})
        self.headers.update({"Gov-Client-Local-IPs": self.config['LOGIN_INFO']['IP']})
        self.headers.update({"Gov-Client-Local-IPs-Timestamp": self.config['LOGIN_INFO']['TIME']})
        self.headers.update({"Gov-Client-MAC-Addresses": self.config['LOGIN_INFO']['MAC']})
        self.headers.update({"Gov-Client-Multi-Factor": self.config['LOGIN_INFO']['MFA']})
        self.headers.update({"Gov-Client-Screens": f"width={self.config['AGENT_INFO']['SCREEN']['WIDTH']}&height={self.config['AGENT_INFO']['SCREEN']['HEIGHT']}&scaling-factor={self.config['AGENT_INFO']['SCREEN']['SCALING']}&colour-depth={self.config['AGENT_INFO']['SCREEN']['COLOUR']}"})
        if(self.config['LOGIN_INFO']['TZ'] == 'BST'):
            self.headers.update({"Gov-Client-Timezone": "UTC+01:00"})
        else:
            self.headers.update({"Gov-Client-Timezone": "UTC+00:00"})
        self.headers.update({"Gov-Client-User-Agent": f"os-family={self.EncodeString(self.config['AGENT_INFO']['SYSTEM'])}&os-version={self.EncodeString(self.config['AGENT_INFO']['RELEASE'])}&device-manufacturer={self.EncodeString(self.config['AGENT_INFO']['MANUFACTURER'])}&device-model={self.EncodeString(self.config['AGENT_INFO']['PRODUCT'])}"})
        self.headers.update({"Gov-Client-User-IDs": f"os={self.EncodeString(self.config['DEVICE_INFO']['DOMAIN'])}&my-application={self.EncodeString(self.config['USER_INFO']['USER_NAME'])}"})
        self.headers.update({"Gov-Client-Window-Size": f"width={self.config['AGENT_INFO']['SCREEN']['W_WIDTH']}&height={self.config['AGENT_INFO']['SCREEN']['W_HEIGHT']}"})
        self.headers.update({"Gov-Vendor-License-IDs": f"my-licensed-application={self.config['DEVICE_INFO']['LICENSE']}"})
        self.headers.update({"Gov-Vendor-Product-Name": f"{self.config['VERSION_INFO']['APP_NAME']}"})
        self.headers.update({"Gov-Vendor-Version": f"my-application={self.config['VERSION_INFO']['APP_VERSION']}"})
        return self.headers

    def RequestNewRefreshToken(self) -> str:
        #sanity check
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return ''
        global AUTH_CODE
        global AUTH_STATE
        #get access key
        self.session = OAuth2Session(client=BackendApplicationClient(client_id=self.config['APP_CONFIG']['CLIENT_ID']), scope=["default"])
        self.access_token = self.session.fetch_token(token_url=f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_id=self.config['APP_CONFIG']['CLIENT_ID'], client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True)['access_token']
        #get refresh token
        self.session = OAuth2Session(self.config['APP_CONFIG']['CLIENT_ID'], scope=["read:vat", "write:vat"], redirect_uri=f"http://localhost:{self.config['APP_CONFIG']['URI_PORT']}/")
        auth_url, state = self.session.authorization_url(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/authorize")
        #open url in default browser
        print("Redirecting to web browser...")
        webbrowser.open(auth_url, new=2, autoraise=True)
        handler = RedirectParser
        try:
            with socketserver.TCPServer(("", self.config['APP_CONFIG']['URI_PORT']), handler) as httpd:
                httpd.handle_request()
                httpd.server_close()
        except Exception:
            print("Too many frequent requests!")
            return 0
        pyautogui.hotkey('ctrl','w')
        #catch redirect
        redirect_response = f"https://localhost:{self.config['APP_CONFIG']['URI_PORT']}/?code={AUTH_CODE}&state={AUTH_STATE}"
        #get token
        return self.session.fetch_token(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True, authorization_response=redirect_response)['refresh_token']

    def ExchangeRefreshToken(self, token) -> str:
        #sanity check
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return ''
        self.session = OAuth2Session(self.config['APP_CONFIG']['CLIENT_ID'], scope=["read:vat", "write:vat"])
        self.response = self.session.refresh_token(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_id=self.config['APP_CONFIG']['CLIENT_ID'], client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True, refresh_token=token)
        self.access_token = self.response['access_token']
        return self.response['refresh_token']

    def SelectClient(self, id) -> int:
        if id == None:
            self.active_client = ''
            self.client_index = None
            return 0
        index = self. GetClientIndex(id)
        if index == None:
            print("Client does not exist!")
            return 1
        self.client_index = index
        self.active_client = self.config['DATABASE_INFO'][index]['CLIENT_ID']
        #get access token
        try:
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.ExchangeRefreshToken(self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'])
            self.SaveConfig()
            return 0
        except Exception:
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.RequestNewRefreshToken()
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.ExchangeRefreshToken(self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'])
            self.SaveConfig()
            return 0

    def VerifyVatNumber(self, no) -> int:
        try:
            vat_no = int(no)
            if vat_no < 0 or vat_no > 999999999:
                print('Invalid VAT number!')
                return -1
        except Exception:
            print('Invalid VAT number!')
            return -1
        return vat_no

    def CheckVatNumber(self, vat_no):

        self.PopulateHeaders()
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/check-vat-number/lookup/{vat_no}", headers=self.headers)
        return self.response.json()

    def PrintObligations(self, obs, quiet):
        try:
            l = len(obs['obligations'])
            if quiet == False and l > 0:
                print(f"Period Key\tPeriod Start\tPeriod End\tStatus\t\tPayment Date")
                for ob in obs['obligations']:
                    if ob['status'] == 'O':
                        stat = f"Open\t\t{ob['due']}"
                    else:
                        stat = f"Fulfilled\t{ob['received']}"
                    print(f"{ob['periodKey']}\t\t{ob['start']}\t{ob['end']}\t{stat}")
            return l
        except Exception:
            return -1

    def RetrieveObligationsByStatus(self, status, quiet=False) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        if status == 'O' or status == 'F':
            self.PopulateHeaders()
            self.headers.update({"Authorization": f"Bearer {self.access_token}"})
            self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/obligations?status={status}", headers=self.headers)
            obs = self.response.json()
            n = self.PrintObligations(obs, quiet)
            if n < 0:
                return -1
            return n
        else:
            return -1

    def RetrieveObligationsByDate(self, start_date, end_date, quiet=False) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/obligations?from={start_date}&to={end_date}", headers=self.headers)
        obs = self.response.json()
        return self.PrintObligations(obs, quiet)

    def ViewReturn(self, period_key) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/returns/{period_key}", headers=self.headers)
        if self.response.status_code != 200:
            print("Not found!")
            return -1
        return 0
    
    def DisplayReturn(self, vat_return) -> int:
        print(f"PeriodKey: {vat_return['periodKey']}")
        print(f"1. VAT due on sales: {vat_return['vatDueSales']}")
        print(f"2. VAT due on acquisitions: {vat_return['vatDueAcquisitions']}")
        print(f"3. Total VAT due: {vat_return['totalVatDue']}")
        print(f"4. Total VAT reclaimed: {vat_return['vatReclaimedCurrPeriod']}")
        print(f"5. Net VAT due: {vat_return['netVatDue']}")
        print(f"6. Total value of sales: {vat_return['totalValueSalesExVAT']}")
        print(f"7. Total value of purchases: {vat_return['totalValuePurchasesExVAT']}")
        print(f"8. Total value of supplies: {vat_return['totalValueGoodsSuppliedExVAT']}")
        print(f"9. Total value of acquisitions: {vat_return['totalAcquisitionsExVAT']}")
        return 0

    def SubmitReturn(self, vat_return) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Content-Type": "application/json"})
        self.headers.update({"Connection": "keep-alive"})
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.post(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/returns", headers=self.headers, data=json.dumps(vat_return))
        return 0

    def RetrieveLiabilities(self, start_date, end_date) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/liabilities?from={start_date}&to={end_date}", headers=self.headers)
        return 0

    def ViewPayments(self, start_date, end_date) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/payments?from={start_date}&to={end_date}", headers=self.headers)
        return 0
    
    def ValidateHeaders(self):
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}test/fraud-prevention-headers/validate", headers=self.headers)
        return self.response.json()
    
    def HeaderFeedback(self):
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}test/fraud-prevention-headers/vat-mtd/validation-feedback", headers=self.headers)
        return self.response.json()


    def ShellHelp(self) -> int:
        print(f"check - check details of a GB VAT number")
        print(f"list - list all client info")
        print(f"create - create new client")
        print(f"select - select client by ID")
        print(f"retrieve - retrieve VAT obligations by status or date-range")
        print(f"return - submit VAT return for period")
        print(f"view - view submitted VAT return")
        print(f"liability - view outstanding VAT liabilities")
        print(f"payments - view payments received by HMRC")
        print(f"exit/quit - exit the program")
        return 0

    def ShellCheck(self):
        vat_no = input('Enter VAT number: ')
        try:
            if(self.VerifyVatNumber(vat_no) < 0):
                return -1
            self.response = self.CheckVatNumber(vat_no)
            print(f"{self.response['target']['name']} - {self.response['target']['address']['line1']}, {self.response['target']['address']['postcode']}")
            return 0
        except Exception:
            print('VAT number not found!')
            return -1
        
    def ShellList(self) -> int:
        cl = self.config['DATABASE_INFO']
        if len(cl) == 0:
            print('No clients exist!')
            return -1
        for c in cl:
            act = self.active_client
            sel = ''
            #if previously selected
            if self.active_client == c['CLIENT_ID'] and self.client_index == cl.index(c):
                sel = '* '
            #select client
            self.SelectClient(c['CLIENT_ID'])
            #search for no. outstanding obligations
            n = self.RetrieveObligationsByStatus("O", quiet=True)
            #reselect
            if act != '':
                self.SelectClient(act)
            else:
                self.SelectClient(None)
            #print
            print(f"{sel}{c['CLIENT_ID']} - {'NaN' if n == -1 else n} item{'s' if n != 1 else ''} outstanding")
        return 0
    
    def ShellCreate(self):
        self.client_index = ''
        self.active_client = ''
        id = str(input('Enter Client ID: '))
        cl = self.config['DATABASE_INFO']
        if len(cl) > 0:
            for c in cl:
                if id == c['CLIENT_ID']:
                    print('Client ID already exists!')
                    return -1
        vat_no = input('Enter VAT number: ')
        no = self.VerifyVatNumber(vat_no)
        if no < 0:
            return -1
        try:
            fr = int(input('Enter Flat Rate (enter 0 for standard-rate VAT scheme): '))
            if fr < 0 or fr > 20:
                print('Invalid Flat Rate!')
                return -1
        except Exception:
            print('Invalid Flat Rate!')
            return -1
        try:
            qtr = int(input('Enter VAT quarter (0=Jan, 1=Feb, 2=Mar): '))
            if qtr < 0 or qtr > 2:
                print('Invalid quarter!')
                return -1
        except Exception:
            print('Invalid quarter!')
            return -1
        st = str(input("Enter start date (YYYY-MM-DD): "))
        inp = input("Enter end date (YYYY-MM-DD, or 0 for none): ")
        try:
            end = int(inp)
            if end < 0 or end > 0:
                print('Invalid end date!')
                return -1
        except Exception:
            end = str(inp)

        newcl = {}
        newcl.update({"CLIENT_ID": id})
        newcl.update({"VAT_NO": no})
        newcl.update({"REFRESH_TOKEN": 0})
        newcl.update({"FLAT_RATE": fr})
        newcl.update({"VAT_QUARTER": qtr})
        newcl.update({"START_DATE": st})
        newcl.update({"END_DATE": end})
        newcl.update({"RETURNS": []})
        #save to config
        self.config['DATABASE_INFO'].append(newcl)
        self.SaveConfig()
        self.SelectClient(self.config['DATABASE_INFO'][self. GetClientIndex(id)]['CLIENT_ID'])

        return 0

    def ShellRetrieve(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        m = str(input(f"Select filter (open/date): "))
        if m != 'open' and m != 'date':
            print("Invalid filter!")
            return -1
        if m == 'date':
            try:
                yr = int(input("Enter year (YYYY): "))
            except Exception:
                print("Invalid year!")
                return -1
            st = f"{str(yr)}-01-01"
            en = f"{str(yr)}-12-31"
            if self.RetrieveObligationsByDate(st, en) == -1:
                print("Not found!")
        else:
            if self.RetrieveObligationsByStatus('O') == -1:
                print("Not found!")
        return 0
    
    def ShellReturn(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        pk = str(input("PeriodKey: "))
        if pk == '' or pk == 'exit' or pk == 'quit':
            return -1
        for ret in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            if ret['PERIOD_KEY'] == pk:
                print('Already submitted!')
                return -1
        try:
            ds = float(input("1. VAT due on sales: "))
            da = float(input("2. VAT due on acquisitions: "))
            dt = ds + da
            print(f"3. Total VAT due: {dt:10.2f}")
            dr = float(input("4. Total VAT reclaimed: "))
            dn = dt - dr
            print(f"5. Net VAT due: {dn:10.2f}")
            ts = float(input("6. Total value of sales: "))
            tp = float(input("7. Total value of purchases: "))
            tl = float(input("8. Total value of supplies: "))
            ta = float(input("9. Total value of acquisitions: "))
        except Exception:
            print("Input must be an int or float!")
            return -1
        
        vat_return = {}
        vat_return.update({'periodKey': pk})
        vat_return.update({'vatDueSales': ds})
        vat_return.update({'vatDueAcquisitions': da})
        vat_return.update({'totalVatDue': float(f"{dt:10.2f}")})
        vat_return.update({'vatReclaimedCurrPeriod': dr})
        vat_return.update({'netVatDue': float(f"{dn:10.2f}")})
        vat_return.update({'totalValueSalesExVAT': ts})
        vat_return.update({'totalValuePurchasesExVAT': tp})
        vat_return.update({'totalValueGoodsSuppliedExVAT': tl})
        vat_return.update({'totalAcquisitionsExVAT': ta})

        fin = str(input("Finalised? [Y/n]: "))
        if fin == 'Y':
            cfm = str(input("Are you sure you want to submit a finalised return? [Y/n]: "))
            if cfm != 'Y':
                return -1
            vat_return.update({'finalised': True})
            print("Submitting VAT return...")
            if self.SubmitReturn(vat_return) == 0:
                try:
                    print(self.response.json()['code'])
                    return -1
                except Exception:
                    return_info = {}
                    return_info.update({"PERIOD_KEY": pk})
                    return_info.update({"RECEIPT": self.response.json()})
                    self.config['DATABASE_INFO'][self.client_index]['RETURNS'].append(return_info)
                    self.SaveConfig()
                    return 0
        
    def ShellView(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        pk = str(input('Enter Period Key: '))
        for ret in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            if ret['PERIOD_KEY'] == pk:
                try:
                    self.DisplayReturn(ret['RETURN'])
                    return 0
                except Exception:
                    pass
        try:
            if self.ViewReturn(pk) < 0:
                return -1
            self.DisplayReturn(self.response.json())
            self.config['DATABASE_INFO'][self.client_index]['RETURNS'][self.GetReturnIndex(pk)].update({"RETURN": self.response.json()})
            self.SaveConfig()
            return 0
        except Exception:
            pass
        return 1

    def ShellLiabilities(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        try:
            yr = int(input("Enter year (YYYY): "))
        except Exception:
            print("Invalid year!")
            return -1
        st = f"{str(yr)}-01-01"
        en = f"{str(yr)}-12-31"
        self.RetrieveLiabilities(st, en)
        try:
            print(self.response.json()['code'])
            return -1
        except Exception:
            first = True
            for paym in self.response.json()['liabilities']:
                if paym['outstandingAmount'] != 0:
                    if first == True:
                        print(f" Amount (£)\tDue")
                        first = False
                    print("{:>10}".format(f"{paym['outstandingAmount']:,.2f}"), end='')
                    try:
                        print(f"\t{paym['due']}")
                    except Exception:
                        print()
            return 0


    def ShellPayments(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        try:
            yr = int(input("Enter year (YYYY): "))
        except Exception:
            print("Invalid year!")
            return -1
        st = f"{str(yr)}-01-01"
        en = f"{str(yr)}-12-31"
        self.ViewPayments(st, en)
        try:
            print(self.response.json()['code'])
            return -1
        except Exception:
            print(f" Amount (£)\tDate")
            for paym in self.response.json()['payments']:
                print("{:>10}".format(f"{paym['amount']:,.2f}"), end='')
                try:
                    print(f"\t{paym['received']}")
                except Exception:
                    print()
            return 0


    def Run(self):
            try:
                while True:
                    cmd = input('Enter Command: ')
                    if cmd == 'help' or cmd == '':
                        self.ShellHelp()
                    elif cmd == 'check':
                        self.ShellCheck()
                    elif cmd == 'list':
                        self.ShellList()
                    elif cmd == 'create':
                        self.ShellCreate()
                    elif cmd == 'select':
                        id = str(input('Enter Client ID: '))
                        self.SelectClient(id)
                    elif cmd == 'retrieve':
                        self.ShellRetrieve()
                    elif cmd == 'return':
                        self.ShellReturn()
                    elif cmd == 'view':
                        self.ShellView()
                    elif cmd == 'liability':
                        self.ShellLiabilities()
                    elif cmd == 'payments':
                        self.ShellPayments()
                    elif cmd == 'exit' or cmd == 'quit':
                        sys.exit(0)
                    else:
                        print('Invalid command! Type \'help\' for list of commands')
            except KeyboardInterrupt:
                sys.exit(0)

