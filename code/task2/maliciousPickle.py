import os

from fickling.pickle import Pickled
import pickle
# https://www.cadosecurity.com/linux-attack-techniques-dynamic-linker-hijacking-with-ld-preload/ -attacks

BAD_LIBRARY={'/etc/hosts', '/bin/sh','/etc/passwd','/etc/pam.conf','/proc'}
# This technique is often called DLL injection on Windows.
# With DLL injection, the attacker creates a malicious library with the same name and API as the good one.
# The program loads the malicious library and it, in turn, loads the good one and it will call the good one as needed to do the operations that the original program wants.
BAD_CALLS = {'os', 'shutil', 'sys', 'requests', 'net','ls'}
BAD_SIGNAL = {'eval','rm ', 'cat ', 'nc ','exec','open'}
BAD_FILES={'.py','.exe','.dll','.so'}

# Create a malicious pickle
data = "real data"
pickle_bin = pickle.dumps(data)
p = Pickled.load(pickle_bin)
p.insert_python_exec("with open('/etc/hosts','r') as r: print(r.readlines())")
p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
with open('payload.pkl', 'wb') as f:
    p.dump(f)



def scann(scan):
    result_output=""
    result_total = 0
    result_other = 0
    result_calls = {}
    result_signals = {}
    result_files={}
    result_library={}

    for call in BAD_CALLS:
        result_calls[call] = 0

    for signal in BAD_SIGNAL:
        result_signals[signal] = 0
    for file in BAD_FILES:
        result_files[file] = 0
    for lib in BAD_LIBRARY:
        result_library[lib] = 0

    input=scan
    for call in BAD_CALLS:
            if (input.find(call) == 0):
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
                result_files[signal] += 1
                result_total += 1
                result_output += "\n----- found malicious file (" + file + ") -----\n"
                result_output += input

    for lib in BAD_LIBRARY:
            if (input.find(lib) > -1):
                result_library[lib] += 1
                result_total += 1
                result_output += "\n----- found malicious signal (" + lib + ") -----\n"
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
          print("non-standard calls: " + str(result_other))
          print("total: " + str(result_total))
          print("")
          print("SCAN FAILED")


          print(result_output)
          print(result_total)
    else:
          print("SCAN PASSED!")
# innocently unpickle and get your friend's data
with open('payload.pkl', 'rb') as f:
    # data = pickle.load(f)
    # print(data)
    # print(str(f.read()))
    scann(str(f.read()))
    # os.system("hexyl payload.pkl")





# cat payload.pkl




