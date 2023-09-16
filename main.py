#!/usr/bin/python3

import sys
import online_tax_services

CONFIG_FILE = './config.json'

if __name__ == "__main__":

    ots = online_tax_services.OnlineTaxServices(CONFIG_FILE)

    if ots.run_mode == 'INSTALL':
        if ots.Install() != 0:
            print("Install failed! Exiting...")
            sys.exit(1)
        sys.exit(0)
    elif ots.run_mode == 'GENERATE':
        if ots.GenerateSecret() != 0:
            print("TOTP generator failed! Exiting...")
            sys.exit(1)
        sys.exit(0)

    if ots.run_mode != 'SHELL':
        print('Invalid run mode! Exiting...')
        sys.exit(1)

    ic = input(f"Enter OTP: ")
    if ots.CheckOtp(ic) != 0:
        print("Invalid OTP! Exiting...")
        sys.exit(1)

    ots.Run()
