# Undergraduate-final-project-in-Cyber-Security
## Pickle file
The pickle module in Python provides functions for serializing and deserializing Python objects into a binary format. The module defines two main classes: Pickler and Unpickler, which are used to serialize and deserialize Python objects, respectively.

The Pickler class is used to convert a Python object into a byte stream, while the Unpickler class is used to convert a byte stream back into a Python object.

The pickle module also defines several functions for serializing and deserializing objects, including:

- pickle.dump(obj, file, protocol=None, *, fix_imports=True)
  - This function serializes the object 'obj' and writes it to the open file object 'file'. The 'protocol' argument is an optional integer that specifies the pickle protocol to use.

- pickle.dumps(obj, protocol=None, *, fix_imports=True)
  - This function serializes the object 'obj' and returns a bytes object containing the serialized data. The 'protocol' argument is an optional integer that specifies the pickle protocol to use.

- pickle.load(file, *, fix_imports=True, encoding="ASCII", errors="strict")
  - This function reads a pickled object from the open file object 'file' and returns the deserialized Python object.

- pickle.loads(bytes_object, *, fix_imports=True, encoding="ASCII", errors="strict")
  - This function deserializes a pickled object from the bytes object 'bytes_object' and returns the deserialized Python object.

The pickle module uses a binary format to serialize Python objects, which consists of a series of bytes that represent the object in a compact and efficient way. The format includes a protocol version number, a serialized representation of the object's data, and a series of instructions that describe how to recreate the object. The format is designed to be flexible and extensible, and can handle a wide range of Python objects.

## Overview of Pickle Files

1. `malicious_socket.pkl`: This pickle file contains a malicious `socket` object. When the object is unpickled, it returns a new `socket` object with the address family set to `AF_INET` and the socket type set to `SOCK_STREAM`. This can be used to establish a network connection and potentially execute malicious code on the target machine.

2. `malicious_exec.pkl`: This pickle file contains a malicious `ExecuteCode` object that, when unpickled along with a list of values, executes the arbitrary code `"import os; os.system('echo I am executing arbitrary code!')"`. This can be used to execute any arbitrary code on the target machine.  
The `exec()` function in Python is used to execute a block of code dynamically at runtime. While it can be a powerful tool for experienced developers to create dynamic and flexible programs, it can also be dangerous in the hands of attackers or inexperienced programmers.
One of the main reasons why the `exec()` function can be dangerous is that it allows arbitrary code execution. This means that any string passed to the function can be executed as Python code, including code that could potentially be harmful.
For example, an attacker could use the `exec()` function to execute malicious code that could delete files, modify system settings, or even take control of the entire system. Additionally, the `exec()` function can make it difficult to track down bugs or errors in code, as errors may only be discovered at runtime.

3. `student_file.pkl`: This pickle file contains a list of student names, but there is no malicious attack associated with it.

4. `malicious_eval.pkl`: This pickle file contains a malicious `EvalCode` object that, when unpickled, executes the code `"['a', 'b', 'c']"`. This can be used to execute arbitrary code on the target machine.    
The `eval()` function in Python is considered dangerous because it executes arbitrary code as a string input. This means that any string passed to `eval()` will be executed as if it were a Python statement. If the string contains malicious code, it can have unintended consequences and cause security vulnerabilities.
An attacker could exploit the `eval()` function to execute arbitrary code by passing in malicious code as a string. This can be particularly dangerous if the input string comes from an untrusted source, such as user input, as it can allow attackers to execute arbitrary code on the target system.
For example, consider the following code: ```
user_input = input("Enter a Python expression: ")
result = eval(user_input)
print(result)```  
An attacker could pass in a malicious expression as input, such as `__import__('os').system('rm -rf /')`, which would execute the `rm -rf /` command on the system, resulting in the deletion of all files on the root directory.
Therefore, it is recommended to avoid using `eval()` on untrusted input and instead use alternative methods, such as parsing or sanitizing the input before executing it.  
5. `malicious_compile.pkl`: This pickle file contains a malicious `CompileCode` object that, when unpickled, executes the code `"print('I execute code that runs on your computer')"` and returns the compiled code object. This can be used to execute arbitrary code on the target machine.
This file is dangerous because it defines a custom serialization method `__reduce__` that returns a tuple containing the `compile()` function and its arguments. When this object is deserialized with `pickle.load()`, the `compile()` function is executed with the given arguments.
In this specific case, the `compile()` function is used to compile and execute the string `"print('I execute code that runs on your computer')"`. This means that when the object is unpickled, this code will be executed on the user's machine, which could potentially be dangerous if the code being executed is malicious. 
An attacker could craft a pickle payload that contains a `CompileCode` object that executes arbitrary code when deserialized. When this pickle is loaded by the victim, the code would execute and could cause harm to the system or compromise its security.

6. `malicious_open.pkl`: This pickle file contains a malicious `OpenFile` object that, when unpickled, executes the code `"f = open('/etc/passwd', 'r'); print(f.read()); f.close()"`. This can be used to read any file on the target machine.
This file defines a class `OpenFile` with a `__reduce__()` method that returns a tuple of `exec()` function and a string argument. The `exec()` function takes a string as an argument and executes it as Python code. In this case, the string argument opens the `/etc/passwd` file and prints its contents to the console.
This is dangerous because it allows an attacker to execute arbitrary code on the target machine. By exploiting the pickle module's `__reduce__()` method, an attacker can execute code that they choose and have it executed with the privileges of the process that is unpickling the malicious pickle. In this case, an attacker could use this code to gain unauthorized access to sensitive data on the target machine. It is important to never unpickle data from untrusted sources or to use the pickle module with untrusted data.  
7. `fruits.pkl`: This pickle file contains a list of fruit names, but there is no malicious attack associated with it.

8. `person_dictionary.pkl`: This pickle file contains a dictionary of personal information, but there is no malicious attack associated with it.

9. `safe_os.pkl`: This pickle file contains a safe `Os` object that, when unpickled, executes the code `"echo 'Hello, world!'"` using the `system()` function from the `os` module. This is not a malicious attack.

10. `unsafe.pkl`: This pickle file contains a maliciously crafted `Pickled` object that, when unpickled, executes several lines of code, including `with open('/etc/passwd','r') as r: print(r.readlines())`, `with open('/etc/group','r') as r: print(r.readlines())`, and `os.system('echo Malicious code!')`. This can be used to read sensitive files and execute arbitrary code on the target machine.  
The file `unsafe.pkl` is dangerous because it contains malicious code that can be executed when the file is loaded using the `pickle` module. 
The code creates a list of student names and then pickles it using the `pickle.dumps()` method. It then loads the pickled object into a `Pickled` object and inserts four different lines of malicious code using the `insert_python_exec()` method. 
The first two lines of malicious code open and read the `/etc/passwd` and `/etc/group` files, which can be a serious security risk as these files contain sensitive information about users and groups on the system. 
The third line of code imports a module named `module` and prints the string "malicious". This may seem harmless, but importing unknown modules can be a security risk as the module could contain malicious code. 
The fourth line of code uses the `os.system()` method to execute the shell command "echo Malicious code!", which can be a serious security risk as it allows arbitrary code execution on the system. 
When the pickled object is loaded and unpickled using the `pickle.load()` method, the malicious code will be executed, potentially causing serious harm to the system. Therefore, it is important to be careful when loading pickled objects from untrusted sources and to only load pickled objects that come from trusted sources.
