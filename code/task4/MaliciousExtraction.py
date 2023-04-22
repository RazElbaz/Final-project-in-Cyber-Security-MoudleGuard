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
calls = []
non_setstate_calls = []

'''
This is an example of a custom Unpickler class in Python's pickle module. The Unpickler class is responsible for deserializing pickled objects, which involves converting a serialized representation of an object back into a live object in memory.
The MyUnpickler class overrides the find_class method of the base Unpickler class. This method is called by the Unpickler when it encounters a serialized object that needs to be deserialized. The find_class method takes two arguments: module and name. module is the name of the module that contains the class, and name is the name of the class itself.
The MyUnpickler class only allows the unpickling of a class named MySafeClass. If it encounters any other class name, it raises an UnpicklingError with a message indicating that the class is not allowed to be unpickled.
By using this custom Unpickler class, you can ensure that only specific classes are allowed to be unpickled from a pickle file, which can help prevent security vulnerabilities.
'''


class MySafeClass:
    def __init__(self, name):
        self.name = name


class MyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == 'MySafeClass':
            return MySafeClass
        else:
            return None  # Return None instead of raising an exception


class TrustedClass:
    def __init__(self, value):
        self.value = value

    def __reduce__(self):
        return (type(self), (self.value,))


class MaliciousClass:
    def __init__(self, value):
        self.value = value

    def __reduce__(self):
        def harmless_function():
            print("This is a harmless function.")

        return harmless_function, ()


def is_safe(obj):
    """Verify that the __reduce__() method of the object does not contain any malicious code."""
    if isinstance(obj, bytes):
        # Exclude bytes objects
         obj = obj.decode('utf-8')
    reduce_method = obj.__reduce__()
    if isinstance(reduce_method, tuple) and len(reduce_method) == 2:
        function, args = reduce_method
        if isinstance(args, tuple):
            # Check if the string representation of the function and its arguments
            # do not contain any malicious code
            if not re.search("open|eval|exec|system|subprocess|os\.", str(function)) \
                    and all(not re.search("open|eval|exec|system|subprocess|os\.", str(arg)) for arg in args):
                return True
    return False


def malPKL(filename):
    with open(filename, 'rb') as f:
        output = subprocess.check_output(['fickling', '--trace', filename])

        output_str = output.decode()
        # Split the output into separate lines
        lines = output_str.split('\n')

        # Iterate over each line and find lines that contain the variable name
        var_lines = []
        for line in lines:
            if '_var' in line and line[0:4] == '_var':
                var_lines.append(line)
        if len(var_lines)>0:
            print("The malicious data:")
        print(var_lines)

        check = str(f.read())
        # print(check)

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
        print("======================================================")
        # Pickle the data and write it to a new file
        with open('safe.pkl', 'wb') as f:
            p.dump(f)


def scann(scan):
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

#Function for a normal file:
# If the file is correct it will print the correct objects found in it
def verify(filename):
    with open(filename, 'rb') as f:
        unpickler = MyUnpickler(f)
        try:
            objects = unpickler.load(f)
            # Verify that each object is safe to unpickle
            for obj in objects:

                if is_safe(obj):
                    # The object is safe, we can unpickle it
                    unpickled_obj = unpickler.loads(pickle.dumps(obj))
                    print(f"Unpickled object: {unpickled_obj}")
                else:
                    print("Object contains malicious code and will not be unpickled.")
            return obj  # Return the unpickled object
        except Exception as e:
            return None  # Return None if an exception was raised

# Function for a normal file:
# If the file is correct it will print the reduce or ecxec function
def check(filename):
    with open(filename, 'rb') as f:
        # Read the pickle data without loading it
        try:
            # Create an Unpickler object
            unpickler = pickle.Unpickler(f)
            while True:
                obj = unpickler.load()
                if hasattr(obj, '__reduce__'):
                    print(type(obj).__name__, 'has __reduce__ method')
                if isinstance(obj, tuple) and isinstance(obj[0], type) and obj[0].__name__ == 'exec':
                    print(type(obj).__name__, 'contains executed code')

                if is_safe(obj):
                    # The object is safe, we can unpickle it
                    unpickled_obj = pickle.loads(pickle.dumps(obj))
                    print(f"Unpickled object: {unpickled_obj}")
                else:
                    print("Object contains malicious code and will not be unpickled.")

        except Exception as e:
            return None  # Return None if an exception was raised

# Function to check the integrity of a file:
def unpickle(filename):
    with open(filename, 'rb') as f:
        unpickler = MyUnpickler(f)
        try:
            obj = unpickler.load()
            return obj  # Return the unpickled object
        except Exception as e:
            return None  # Return None if an exception was raised


def main():
    filename = 'unsafe.pkl'
    my_check = check(filename)
    my_verify = verify(filename)
    my_object = unpickle(filename)
    if my_object is None:
        result = 1
        print("Error occurred during unpickling")

    else:
        result = 0
        print(f"Unpickled object: {my_object}")

    if result == 1:
        # Handle malicious data
        print("**************************************")
        print("Displays all malicious data....")
        print("**************************************")
        with open(filename, 'rb') as f:
            # data = pickle.load(f)
            # print(data)
            print()
            print("**************************************")
            print("Read the active part of the code")
            print("**************************************")
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
        print("\n\n**************************************")
        print("Now removing the malicious data....")
        print("**************************************")
        malPKL(filename)

        with open('safe.pkl', 'rb') as f:
            # data = pickle.load(f)
            # print(data)
            # print(str(f.read()))
            print("Read the active part of the code")
            scann(str(f.read()))
            # os.system("hexyl unsafe.pkl")
            print("***************************************")
            print("Runs Fickling *static* analysis")
            print("***************************************")
            print("-----------------------------check-safety----------------------------------------")
            # Fickling
            # Fickling is a decompiler, static analyzer, and bytecode rewriter for Python pickle object serializations.
            # Pickled Python objects are in fact bytecode that is interpreted by a stack-based virtual machine built into Python called the "Pickle Machine".
            # Fickling can take pickled data streams and decompile them into human-readable Python code that, when executed, will deserialize to the original serialized object.
            # The authors do not prescribe any meaning to the “F” in Fickling; it could stand for “fickle,” … or something else. Divining its meaning is a personal journey in discretion and is left as an exercise to the reader.
            os.system("fickling --check-safety {}".format('safe.pkl'))
            print("---------------------------------trace-------------------------------------------")
            os.system("fickling --trace {}".format('safe.pkl'))
    elif (result == 0):
        with open(filename, 'rb') as f:
            # data = pickle.load(f)
            # print(data)
            # print(str(f.read()))
            print("**************************************")
            print("Read the active part of the code")
            print("**************************************")
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


    '''
    In Python, you can change the terminal color by printing special escape sequences to the terminal. The escape sequences use ASCII control codes that are interpreted by the terminal emulator to change the color of the text.

    Here's an example of how to change the color of the text to red in the terminal:

    python
    Copy code
    print("\033[91mHello, world!\033[0m")
    The \033 sequence is the escape character in ASCII, and is followed by [ to indicate the beginning of an escape sequence. 91 is the code for the color red, and m indicates the end of the sequence. Hello, world! is the text that will be printed in red. Finally, \033[0m resets the color to the default.
    
    
    print("\033[91mHello, world!\033[0m")
    '''

    # data = unpickler.load()

    # # Serialize the data to JSON
    # json_data = json.dumps({'data': data})
    #
    # # Write the serialized data to a file
    # with open('data.json', 'w') as f:
    #     f.write(json_data)
    #     # cat unsafe.pkl
