#!/usr/bin/env python3.8
#! -*- coding: utf-8 -*-

# Copyright © 2020 Thomas Reddison. All rights reserved.

import winreg
import argparse
import psutil
import os
import requests
import hashlib
import json
from sys import platform, argv
from getpass import getpass

if platform != 'win32':
	print('Only for Windows platforms')
	exit(1)

vt_api_key = ''

parser = argparse.ArgumentParser(description='Program for checking vulnerabilities places in OS Windows')
parser.add_argument('--startup-registry', action='store_true', help='check registry autorun')
# parser.add_argument('--startup-services', action='store_true', help='check services autorun')
parser.add_argument('--startup-folder', action='store_true', help='check Windows startup folder')
parser.add_argument('--file-scan', type=str, metavar='<path_to_file>', help='send file to VirusTotal to get signature analyze result')
parser.add_argument('-d', '--debug', action='store_true', help='enable debug mode')
parser.add_argument(
	'--vt-api-key-file',
	type=str,
	default='C:\\Users\\' + os.environ['username'] + '\\vt_api_key',
	metavar='<path>',
	help='path to file with VirusTotal API key, default is C:\\Users\\%%username%%\\vt_api_key')

if len(argv) == 1:
	parser.print_help()
opts = parser.parse_args()

def print_dict_pretty(dic, tabnum=0):
	for key in dic.keys():
		if type(dic[key]) == dict:
			print('\t' * tabnum + key + ':')
			print_dict_pretty(dic[key], tabnum + 1)
		else:
			print('\t' * tabnum, end='')
			print(f"{key} : {dic[key]}")

def startup_registry():
	registry_startup = {}

	print('[+] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
	values = [winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])]
	for name, value, type_ in values:
		registry_startup[name] = value
		print(f'{name}\t{value}\t{type_}')

	print('[+] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce')
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
	values = [winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])]
	for name, value, type_ in values:
		registry_startup[name] = value
		print(f'{name}\t{value}\t{type_}')

	print('[+] HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
	key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
	values = [winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])]
	for name, value, type_ in values:
		registry_startup[name] = value
		print(f'{name}\t{value}\t{type_}')

	print('[+] HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce')
	key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
	values = [winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])]
	for name, value, type_ in values:
		registry_startup[name] = value
		print(f'{name}\t{value}\t{type_}')

	print()

def startup_folder():
	print('[+] Startup folder for current user')
	startup_folder = os.listdir(
		'C:\\Users\\' +
		os.environ['username'] +
		'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup')
	for file in startup_folder:
		print(file)

	print('[+] Startup folder for all users')
	startup_folder = os.listdir(
		'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup')
	for file in startup_folder:
		print(file)

	print()

def get_from_vt(hashdigest):
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	params = {'apikey': vt_api_key, 'resource': hashdigest}
	response = requests.get(url, params=params)

	return response

def check_file(path):
	sha1 = hashlib.sha1()
	with open(path, 'rb') as f:
		while True:
			data = f.read(1024)
			if not data:
				break
			sha1.update(data)
	print('[+] SHA1 of file: ', sha1.hexdigest())

	response = get_from_vt(sha1.hexdigest())
	if opts.debug:
		print('[*] DEBUG response data:')
		print(response.text)
	try:
		response.json()
	except json.decoder.JSONDecodeError:
		print('[-] Received not JSON format data:\n', response.text)
		exit(1)

	if not response.json()['response_code']:
		url = 'https://www.virustotal.com/vtapi/v2/file/scan'
		params = {'apikey': vt_api_key}
		filename = os.path.basename(path)
		files = {'file': (filename, open(path, 'rb'))}
		requests.post(url, files=files, params=params)
		response = get_from_vt(sha1.hexdigest())
	else:
		print('[*] INFO ')
	print_dict_pretty(response.json())

	print()


def main():
	global vt_api_key

	if opts.debug:
		print('[*] VT API key file path:', opts.vt_api_key_file)
	try:
		vt_api_key = open(opts.vt_api_key_file).read()
		vt_api_key = vt_api_key.replace(' ', '').replace('\n', '')
	except FileNotFoundError:
		print('[*] VirusTotal API key file not found, creating new...')
		vt_api_key = input('Enter API key: ')
		open(opts.vt_api_key_file, 'w').write(vt_api_key)

	if opts.debug:
		print('[*] Your API key: ', vt_api_key)

	if opts.startup_registry:
		startup_registry()
	if opts.startup_folder:
		startup_folder()
	if opts.file_scan:
		try: 
			open(opts.file_scan)
		except FileNotFoundError:
			parser.error('[-] Incorrect path to file')
		check_file(opts.file_scan)

if __name__ == '__main__':
	main()