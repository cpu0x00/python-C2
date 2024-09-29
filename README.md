# python-C2
python3 based command and control

**Discontinued**

- uses Multi-Threaded and Connection pool to handle multiple connections at the same port at the same time
- Base64 Encoded and AES256-CBC Encrypted payload generation for maximum obfuscation (each Agent is completely unique)
- All Communication Happens through SSH Encrypted Sockets
- OS-Specific Simple persistence techniques are implemented 
- python-msf compatible - can make a call back to a meterpreter listener with one command
- upload/download
- AMSI patching functionality
- generator uses pyinstaller and wine to generate OS-Based standalone binaries

 *Disclaimer*

 as mentioned the agents are also python-based, due to this fact the resulted binaries are always huge and im talking about 14 MegaByte Huge so this is not meant to be a first stage agent 
