import ast
import json
import os
import re
import subprocess
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
BAD_SIGNAL = {'eval','compile','rm ', 'cat ', 'nc ','exec','open','run'}
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
BAD_MODULE={"__init__", "__new__", "__reduce__","__builtin__", "os", "subprocess", "sys", "builtins", "socket"}
BAD_IMPORT={'module', 'names','level',}

# Create a malicious pickle
data = "real data"
pickle_bin = pickle.dumps(data)
p = Pickled.load(pickle_bin)
p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
p.insert_python_exec("import module print('malicious')")
p.insert_python_exec("ls -l")

with open('unsafe.pkl', 'wb') as f:
    p.dump(f)
calls=[]
non_setstate_calls=[]

class MySafeClass:
    def __init__(self, name):
        self.name = name

class MyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow MySafeClass to be unpickled
        if name == 'MySafeClass':
            print(name)
            return 0
        else:
            return 1


def malPKL(filename):
    with open(filename, 'rb') as f:
        output = subprocess.check_output(['fickling', '--trace', filename])

        output_str = output.decode()
        # print(output_str)
        # Find the start and end index of the REDUCE output
        reduce_start = output_str.index('STOP')
        reduce_end = output_str.index('result')

        # Extract the REDUCE output as a string
        reduce_str = output_str[reduce_start:reduce_end]

        # Remove any leading/trailing whitespace
        reduce_str = output_str.strip()

        # Convert the REDUCE output to a Python object
        # reduce_obj = eval(reduce_str)

        # Split the output into separate lines
        lines = output_str.split('\n')

        # Iterate over each line and find lines that contain the variable name
        var_lines = []
        for line in lines:
            if '_var' in line and  line[0:4] == '_var':
                var_lines.append(line)
        print(var_lines)

        check=str(f.read())
        print(check)

       # Split the file contents into lines
        var_lines = check.split("\n")

        # Remove any lines containing the string "exec"
        var_safe_lines = [line for line in var_lines if "exec" not in line]

        # Join the remaining lines back into a string
        safe_code = "\n".join(var_safe_lines)

        print(safe_code)
        # Save the sanitized pickle file
        pickle_bin = pickle.dumps(safe_code)
        p = Pickled.load(pickle_bin)
       # Pickle the data and write it to a new file
        with open('safe.pkl', 'wb') as f:
            p.dump(f)

def scann(scan):
    print("------------------------------scanning-pickle----------------------------------------")
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
                result_import[impo] += 1
                result_total += 1
                result_output += "\n----- found malicious import (" + impo + ") -----\n"
                result_output += input
    for cm in BAD_CMD:
            if (input.find(cm) > -1):
                result_cmd[impo] += 1
                result_total += 1
                result_output += "\n----- found malicious cmd command (" + cm + ") -----\n"
                result_output += input
    for mod in BAD_MODULE:
            if (input.find(mod) > -1):
                result_moudle[mod] += 1
                result_total += 1
                result_output += "\n----- found malicious module (" + mod + ") -----\n"
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


filename='student_file.pkl'
with open(filename, 'rb') as f:
    unpickler = MyUnpickler(f)

filename='student_file.pkl'
if unpickler == 1:
    malPKL(filename)
    with open('safe.pkl', 'rb') as f:
        # data = pickle.load(f)
        # print(data)
        # print(str(f.read()))
        print("Read the active part of the code")
        scann(str(f.read()))
        # os.system("hexyl unsafe.pkl")
        print("Runs Fickling *static* analysis")
        print("-----------------------------check-safety----------------------------------------")
        # Fickling
        # Fickling is a decompiler, static analyzer, and bytecode rewriter for Python pickle object serializations.
        # Pickled Python objects are in fact bytecode that is interpreted by a stack-based virtual machine built into Python called the "Pickle Machine".
        # Fickling can take pickled data streams and decompile them into human-readable Python code that, when executed, will deserialize to the original serialized object.
        # The authors do not prescribe any meaning to the “F” in Fickling; it could stand for “fickle,” … or something else. Divining its meaning is a personal journey in discretion and is left as an exercise to the reader.
        os.system("fickling --check-safety {}".format('safe.pkl'))
        print("---------------------------------trace-------------------------------------------")
        os.system("fickling --trace {}".format('safe.pkl'))
    # Unpickle the data
else:
    with open(filename, 'rb') as f:
        # data = pickle.load(f)
        # print(data)
        # print(str(f.read()))
        print("Read the active part of the code")
        scann(str(f.read()))
        # os.system("hexyl unsafe.pkl")
        print("Runs Fickling *static* analysis")
        print("-----------------------------check-safety----------------------------------------")
        # Fickling
        # Fickling is a decompiler, static analyzer, and bytecode rewriter for Python pickle object serializations.
        # Pickled Python objects are in fact bytecode that is interpreted by a stack-based virtual machine built into Python called the "Pickle Machine".
        # Fickling can take pickled data streams and decompile them into human-readable Python code that, when executed, will deserialize to the original serialized object.
        # The authors do not prescribe any meaning to the “F” in Fickling; it could stand for “fickle,” … or something else. Divining its meaning is a personal journey in discretion and is left as an exercise to the reader.
        os.system("fickling --check-safety {}".format(filename))
        print("---------------------------------trace-------------------------------------------")
        os.system("fickling --trace {}".format(filename))
    # data = unpickler.load()

# # Serialize the data to JSON
# json_data = json.dumps({'data': data})
#
# # Write the serialized data to a file
# with open('data.json', 'w') as f:
#     f.write(json_data)
#     # cat unsafe.pkl


