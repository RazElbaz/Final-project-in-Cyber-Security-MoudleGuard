import ast
import os
import sys
from fickling.pickle import Pickled
import pickle

# -attacks
# https://www.cadosecurity.com/linux-attack-techniques-dynamic-linker-hijacking-with-ld-preload/
# https://www.cybertriage.com/blog/training/how-to-detect-running-malware-intro-to-incident-response-triage-part-7/

# https://www.beyondtrust.com/blog/entry/important-linux-files-protect
BAD_LIBRARY={'/etc/hosts', '/bin/sh','/etc/passwd','/etc/pam.conf','/proc','/etc/shadow','/etc/profile', '~/.bash_profile', '~/.bash_login', '~/.profile. /home/user/.bashrc', '/etc/bash.bashrc', '/etc/profile.d/','/etc/system.d','/etc/rc.*','/etc/init.*.','/etc/resolv.conf','/etc/gshadow','/etc/pam.d','/bin','/sbin'}
# This technique is often called DLL injection on Windows.
# With DLL injection, the attacker creates a malicious library with the same name and API as the good one.
# The program loads the malicious library and it, in turn, loads the good one and it will call the good one as needed to do the operations that the original program wants.
BAD_CALLS = {'os', 'shutil', 'sys', 'requests', 'net', 'func',
        'args',
        'keywords',}
BAD_SIGNAL = {'eval','compile','rm ', 'cat ', 'nc ','exec','open','run',"__builtin__"}
BAD_FILES={'.py','.exe','.dll','.so'}
# https://redcanary.com/threat-detection-report/techniques/powershell/
# PowerShell -encodedcommand switch
# This detection analytic looks for the execution of powershell.exe with command lines that include variations of the -encodedcommand argument; PowerShell will recognize and accept anything from -e onward, and it will show up outside of the encoded bits.
BAD_COMMAND={'powershell.exe','-e' ,'-en' ,'-enc' , '-enco','ls','base64'}
# Obfuscation and escape characters
# Obfuscation can disrupt detection logic by splitting commands or parameters or inserting extra characters (that are ignored by PowerShell).
# Monitor for the execution of PowerShell with unusually high counts of characters like ^, +, $, and %.
BAD_CHARACTER={'^' ,'+', '$','%'}
# Suspicious PowerShell cmdlets
# Many of our PowerShell detection analytics look for cmdlets, methods, and switches that may indicate malicious activity.
# The following analytic is by no means exhaustive but offers a few valuable examples of suspicious cmdlets and other oft-abused features to look out for:
BAD_CMD={'-nop', '-noni','invoke-expression' ,'iex' , '.downloadstring' ,'downloadfile'}
BAD_MODULE={"__builtin__", "os", "subprocess", "sys", "builtins", "socket"}
BAD_IMPORT={'module', 'names','level',}

# Create a malicious pickle
data = "real data"
pickle_bin = pickle.dumps(data)
p = Pickled.load(pickle_bin)
p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
p.insert_python_exec("import module print('malicious')")
p.insert_python_exec("ls -l")
with open('payload.pkl', 'wb') as f:
    p.dump(f)
calls=[]
non_setstate_calls=[]


def scann(scan):
    result_output=""
    result_total = 0
    result_other = 0
    result_calls = {}
    result_signals = {}
    result_files={}
    result_library={}
    result_cmd={}
    result_moudle={}
    result_import={}

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

    input=scan
    for call in BAD_CALLS:
            if (input.find(call) > -1):
                print(call)
                result_calls[call] += 1
                result_total += 1
                result_output += "\n----- found lib call (" + call + ") -----\n"
                result_output += input

    for signal in BAD_SIGNAL:
            if (input.find(signal) > -1):
                result_signals[signal] += 1
                result_total += 1
                result_output += "\n----- found malicious signal (" + signal + ") -----\n"
                result_output += input

    for file in BAD_FILES:
            if (input.find(file) > -1):
                result_files[file] += 1
                result_total += 1
                result_output += "\n----- found malicious file (" + file + ") -----\n"
                result_output += input

    for lib in BAD_LIBRARY:
            if (input.find(lib) > -1):
                result_library[lib] += 1
                result_total += 1
                result_output += "\n----- found malicious signal (" + lib + ") -----\n"
                result_output += input

    for impo in BAD_IMPORT:
            if (input.find(impo) > -1):
                print(impo)
                result_import[impo] += 1
                result_total += 1
                result_output += "\n----- found malicious import (" + impo + ") -----\n"
                result_output += input
    for cm in BAD_CMD:
            if (input.find(cm) > -1):
                print(impo)
                result_cmd[impo] += 1
                result_total += 1
                result_output += "\n----- found malicious cmd command (" + cm + ") -----\n"
                result_output += input
    for mod in BAD_MODULE:
            if (input.find(mod) > -1):
                print(mod)
                result_moudle[mod] += 1
                result_total += 1
                result_output += "\n----- found malicious module (" + mod + ") -----\n"
                result_output += input

    if (
            input.find("numpy.") != 0 and
            input.find("_codecs.") != 0 and
            input.find("collections.") != 0 and
            input.find("torch.") != 0):
            result_total += 1
            result_other += 1
            result_output += "\n----- found non-standard lib call -----\n"
            result_output += input


    if (result_total > 0):
          for file in BAD_FILES:
            print("malicious file (" + file + "): " + str(result_files[file]))
          for lib in BAD_LIBRARY:
            print("malicious lib (" + lib + "): " + str(result_library[lib]))
          for call in BAD_CALLS:
            print("library call (" + call + ".): " + str(result_calls[call]))
          for signal in BAD_SIGNAL:
            print("malicious signal (" + signal + "): " + str(result_signals[signal]))
          for c in BAD_CMD:
            print("malicious cmd command (" + c + "): " + str(result_cmd[c]))
          for m in BAD_MODULE:
            print("malicious module (" + m + "): " + str(result_moudle[m]))
          for i in BAD_IMPORT:
            print("malicious import (" + i + "): " + str(result_import[i]))
          print("non-standard calls: " + str(result_other))
          print("total: " + str(result_total))
          print("")
          print("SCAN FAILED")


          print(result_output)
          print(result_total)
    else:
          print("SCAN PASSED!")

with open('payload.pkl', 'rb') as f:
    # data = pickle.load(f)
    # print(data)
    # print(str(f.read()))
    print("Read the active part of the code")
    scann(str(f.read()))
    # os.system("hexyl payload.pkl")
    print("Runs Fickling *static* analysis")
    print("---------------------check-safety--------------------------------")
    # Fickling
    # Fickling is a decompiler, static analyzer, and bytecode rewriter for Python pickle object serializations.
    # Pickled Python objects are in fact bytecode that is interpreted by a stack-based virtual machine built into Python called the "Pickle Machine".
    # Fickling can take pickled data streams and decompile them into human-readable Python code that, when executed, will deserialize to the original serialized object.
    # The authors do not prescribe any meaning to the “F” in Fickling; it could stand for “fickle,” … or something else. Divining its meaning is a personal journey in discretion and is left as an exercise to the reader.
    os.system("fickling --check-safety {}".format('payload.pkl'))
    print("------------------------trace-----------------------------")
    os.system("fickling --trace {}".format('payload.pkl'))

    # cat payload.pkl


