import ast
import json
import os
import re
import subprocess
import sys
from fickling.pickle import Pickled
import pickle
import _pickle as cPickle

from termcolor import colored
# -attacks
# https://www.cadosecurity.com/linux-attack-techniques-dynamic-linker-hijacking-with-ld-preload/
# https://www.cybertriage.com/blog/training/how-to-detect-running-malware-intro-to-incident-response-triage-part-7/

# https://www.beyondtrust.com/blog/entry/important-linux-files-protect
BAD_LIBRARY = {'/etc/hosts', '/bin/sh', '/etc/passwd', '/etc/pam.conf', '/proc', '/etc/shadow', '/etc/profile',
               '~/.bash_profile', '~/.bash_login', '~/.profile. /home/user/.bashrc', '/etc/bash.bashrc',
               '/etc/profile.d/', '/etc/system.d', '/etc/rc.*', '/etc/init.*.', '/etc/resolv.conf', '/etc/gshadow',
               '/etc/pam.d', '/bin', '/sbin'}
# This technique is often called DLL injection on Windows.
# With DLL injection, the attacker creates a malicious library with the same name and API as the good one.
# The program loads the malicious library and it, in turn, loads the good one and it will call the good one as needed to do the operations that the original program wants.
BAD_CALLS = {'os', 'shutil', 'sys', 'requests', 'net', 'func',
             'args',
             'keywords', }
BAD_SIGNAL = {'eval', 'compile', 'rm ', 'cat ', 'nc ', 'exec', 'open', 'run'}
BAD_FILES = {'.py', '.exe', '.dll', '.so'}
# https://redcanary.com/threat-detection-report/techniques/powershell/
# PowerShell -encodedcommand switch
# This detection analytic looks for the execution of powershell.exe with command lines that include variations of the -encodedcommand argument; PowerShell will recognize and accept anything from -e onward, and it will show up outside of the encoded bits.
BAD_COMMAND = {'powershell.exe', '-e', '-en', '-enc', '-enco', 'ls', 'base64'}
# Obfuscation and escape characters
# Obfuscation can disrupt detection logic by splitting commands or parameters or inserting extra characters (that are ignored by PowerShell).
# Monitor for the execution of PowerShell with unusually high counts of characters like ^, +, $, and %.
BAD_CHARACTER = {'^', '+', '$', '%'}
# Suspicious PowerShell cmdlets
# Many of our PowerShell detection analytics look for cmdlets, methods, and switches that may indicate malicious activity.
# The following analytic is by no means exhaustive but offers a few valuable examples of suspicious cmdlets and other oft-abused features to look out for:
BAD_CMD = {'-nop', '-noni', 'invoke-expression', 'iex', '.downloadstring', 'downloadfile'}
BAD_MODULE = {"__init__", "__new__", "__reduce__", "__builtin__", "os", "subprocess", "sys", "builtins", "socket"}
BAD_IMPORT = {'module', 'names', 'level', }


def scann(scan):
    with open(scan, 'rb') as f:
            print()
            scan=(str(f.read()))
    print("\n******scanning-pickle******")
    result_output = ""
    result_total = 0
    result_other = 0
    result_calls = {}
    result_signals = {}
    result_files = {}
    result_library = {}
    result_cmd = {}
    result_moudle = {}
    result_import = {}

    for call in BAD_CALLS:
        result_calls[call] = 0
    for signal in BAD_SIGNAL:
        result_signals[signal] = 0
    for file in BAD_FILES:
        result_files[file] = 0
    for lib in BAD_LIBRARY:
        result_library[lib] = 0
    for cmd in BAD_CMD:
        result_cmd[cmd] = 0
    for moudle in BAD_MODULE:
        result_moudle[moudle] = 0
    for impor in BAD_IMPORT:
        result_import[impor] = 0

    input = scan
    for call in BAD_CALLS:
        if (input.find(call) > -1):
            result_calls[call] += 1
            result_total += 1
            result_output += "----- found lib call (" + call + ") -----\n"
            result_output += input

    for signal in BAD_SIGNAL:
        if (input.find(signal) > -1):
            result_signals[signal] += 1
            result_total += 1
            result_output += "----- found malicious signal (" + signal + ") -----\n"
            result_output += input

    for file in BAD_FILES:
        if (input.find(file) > -1):
            result_files[file] += 1
            result_total += 1
            result_output += "----- found malicious file (" + file + ") -----\n"
            result_output += input

    for lib in BAD_LIBRARY:
        if (input.find(lib) > -1):
            result_library[lib] += 1
            result_total += 1
            result_output += "----- found malicious signal (" + lib + ") -----\n"
            result_output += input

    for impo in BAD_IMPORT:
        if (input.find(impo) > -1):
            result_import[impo] += 1
            result_total += 1
            result_output += "----- found malicious import (" + impo + ") -----\n"
            result_output += input
    for cm in BAD_CMD:
        if (input.find(cm) > -1):
            result_cmd[impo] += 1
            result_total += 1
            result_output += "----- found malicious cmd command (" + cm + ") -----\n"
            result_output += input
    for mod in BAD_MODULE:
        if (input.find(mod) > -1):
            result_moudle[mod] += 1
            result_total += 1
            result_output += "----- found malicious module (" + mod + ") -----\n"
            result_output += input

    if result_total > 0:
        for file in BAD_FILES:
            if (result_files[file])>0:
                print("malicious file (" + file + "): " + str(result_files[file]))
        for lib in BAD_LIBRARY:
            if (result_library[lib])>0:
                print("malicious lib (" + lib + "): " + str(result_library[lib]))
        for call in BAD_CALLS:
            if (result_calls[call])>0:
                print("library call (" + call + ".): " + str(result_calls[call]))
        for signal in BAD_SIGNAL:
            if (result_signals[signal])>0:
                print("malicious signal (" + signal + "): " + str(result_signals[signal]))
        for c in BAD_CMD:
            if (result_cmd[c])>0:
                print("malicious cmd command (" + c + "): " + str(result_cmd[c]))
        for m in BAD_MODULE:
            if (result_moudle[m])>0:
                print("malicious module (" + m + "): " + str(result_moudle[m]))
        for i in BAD_IMPORT:
            if (result_import[i])>0:
                print("malicious import (" + i + "): " + str(result_import[i]))
        if (result_other)>0:
            print("non-standard calls: " + str(result_other))
        # print("total: " + str(result_total))

        print(colored("SCAN FAILED\n", "red"))

        # print(result_output)
        # print(result_total)
    else:
        print(colored("SCAN PASSED!", "green"))
