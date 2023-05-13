# Undergraduate-final-project-in-Cyber-Security
## Pickle file  
<!-- Pickle File  
+----------------+  
|    Pickle Header       |  
+----------------+  
|      Pickled Data      |  
+----------------+     -->

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
## How to Run:
To call the code, you can run it from the command line using the following command:

```
python attack_cmd.py [attack_type]
```

Replace `[attack_type]` with the type of attack you want to execute. Here are the available options:

- `mal_exec`
- `mal_Pickled`
- `mal_compile`
- `mal_open`
- `mal_eval`
- `malicious_socket`
- `safe_student_file`
- `safe_fruits`
- `safe_person_dictionary`
- `safe_os`

For example, to execute the arbitrary code execution attack, you would run:

```
python attack_cmd.py mal_exec
```

Make sure you have Python installed on your system and that you are in the same directory as the `attack_cmd.py` file when you run the command.  
## The attack types supported by the script

- mal_exec: Executes malicious code using the `exec` function.
- mal_Pickled: Loads a malicious Pickled object from a file and executes it.
- mal_compile: Compiles and executes malicious code using the `compile` function.
- mal_open: Reads malicious code from a file and executes it using the `open` function.
- mal_eval: Executes malicious code using the `eval` function.
- malicious_socket: Creates a malicious socket and listens for connections.
- safe_student_file: Demonstrates safe file handling practices when reading from a file.
- safe_fruits: Demonstrates safe handling of user input by ensuring that only safe inputs are accepted.
- safe_person_dictionary: Demonstrates safe dictionary usage by ensuring that only safe inputs are accepted.
- safe_os: Demonstrates safe usage of the `os` module by ensuring that only safe commands are executed.

The type of attack is passed in as the first argument to the script. For example, to execute the `mal_exec` attack, you would run the script with the command:

```
python attack_cmd.py mal_exec
```

This would call the `mal_exec()` function, which executes malicious code using the `exec` function. 

## Explanation of Multiple Attacks in a Code Snippet Targeting Different Vulnerabilities.
The code snippet appears to include multiple attacks, each of which targets different vulnerabilities. Here is a brief explanation of each attack and their parameters:

1. Arbitrary code execution attack:

   The "ExecuteCode" class contains code that will be executed when it's unpickled. The "__reduce__" method is defined in this class, and it returns the built-in "exec" function along with a string argument that contains the code to be executed. The code to be executed in this case is "import os; os.system('echo I am executing arbitrary code!')". This attack is dangerous because it allows an attacker to execute arbitrary code on the victim's computer, which can be used for various purposes such as stealing sensitive information or damaging the system.

2. Evaluation attack:

   The "EvalCode" class contains code that will be evaluated when it's unpickled. The "__reduce__" method is defined in this class, and it returns the built-in "eval" function along with a string argument that contains the code to be evaluated. The code to be evaluated in this case is "['a', 'b', 'c']". This attack is less dangerous than the arbitrary code execution attack because it only evaluates a string literal, but it still allows an attacker to execute arbitrary code on the victim's computer.

3. Code compilation attack:

   The "CompileCode" class contains code that will be compiled and executed when it's unpickled. The "__reduce__" method is defined in this class, and it returns the built-in "compile" function along with three string arguments that represent the code to be compiled, the name of the code, and the mode in which the code is executed (in this case, "exec"). The code to be compiled and executed in this case is "print('I execute code that runs on your computer')". This attack is similar to the arbitrary code execution attack in that it allows an attacker to execute arbitrary code on the victim's computer.

4. File system access attack:

   The "OpenFile" class contains code that will access the victim's file system when it's unpickled. The "__reduce__" method is defined in this class, and it returns the built-in "exec" function along with a string argument that contains the code to be executed. The code to be executed in this case is "f = open('/etc/passwd', 'r'); print(f.read()); f.close()". This code opens the "/etc/passwd" file, which contains sensitive system information, and prints its contents. This attack is dangerous because it allows an attacker to access sensitive files on the victim's computer.

5. Socket creation attack:

   The "MalSocket" class creates a malicious socket when it's unpickled. The "__reduce__" method is defined in this class, and it returns the built-in "socket.socket" function along with two arguments that specify the socket type and protocol. This attack is dangerous because it allows an attacker to create a socket on the victim's computer that can be used to communicate with other malicious entities.

6. Unsafe pickle attack:

   The "Pickled" class contains an unsafe pickle that allows arbitrary code execution when it's unpickled. The "insert_python_exec" method is defined in this class, and it allows an attacker to insert arbitrary Python code into the pickle. The parameters for this attack are the Python code to be executed when the pickle is unpickled. This attack is dangerous because it allows an attacker to execute arbitrary code on the victim's computer.  
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

## mal_exec
Attack Flow:
         ---------------------------------------------
        |                mal_exec()                     |
         ---------------------------------------------
                  |
                  v
         ---------------------------------------------
        |      Load pickled data from file              |
         ---------------------------------------------
                  |
                  v
         ---------------------------------------------
        |      Check if the pickled object is safe       |
         ---------------------------------------------
                  |
                  v
        ---------------------                    ------------------
       |  If analysis_result is True              |  If analysis_result is False   |
        ---------------------                    ------------------
                  |                                             |
                  v                                             v
         ----------------------------             -------------------------------
        |         Print "clean"       |            |       Scan and remove malicious data       |
         ----------------------------             -------------------------------
                  |                                             |
                  v                                             v
         ----------------------------             -------------------------------
        |    Load pickled data again   |            |  Check if the pickled object is safe again |
         ----------------------------             -------------------------------
                  |                                             |
                  v                                             v
         ----------------------------             -------------------------------
        |        Print "clean"        |            |       Print "not clean"       |
         ----------------------------             -------------------------------



Disarm Flow:

```
                            +----------------------+
                            |   Start Disarm Flow   |
                            +----------------------+
                                        |
                                        |
                                        v
                         +------------------------------+
                         | Check if analysis_result == 1 |
                         +------------------------------+
                                        |
                                        |
                        +-----------------+-----------------+
                        |                 |                 |
                        v                 v                 v
            +-------------------+ +-------------------+ +-------------------+
            |   Clean and Exit  | |   Scanning Check  | |  CDR Check & Fix  |
            +-------------------+ +-------------------+ +-------------------+
            (analysis_result_2=1) (analysis_result_2=0) (analysis_result_2=0)
                        |                 |                 |
                        v                 v                 v
            +-------------------+ +-------------------+ +-------------------+
            |                   | |                   | |                   |
            v                   v v                   v v                   v
    +----------------+  +----------------+  +----------------+  +----------------+
    |  Print Cleaned  |  |  Print Cleaned  |  | Print Not Clean |  | Print Not Clean |
    |    Data Left    |  |    Data Left    |  |  and File Fixed |  |   and Exit...   |
    +----------------+  +----------------+  +----------------+  +----------------+
   (analysis_result_2=1) (analysis_result_2=0) (analysis_result_2=0)          |
                                        |                                    |
                                        v                                    |
                         +------------------------------+                    |
                         |     End Disarm Flow         |                    |
                         +------------------------------+                    |
                                        |                                    |
                                        v                                    |
                            +----------------------+                          |
                            |   End of Function     |                          |
                            +----------------------+                          |
                                        |                                       |
                                        v                                       |
                             +---------------------------------+               |
                             |   End of Control Flow Graph        |               |
                             +---------------------------------+               |
```

In the Disarm Flow, we start by checking if the `analysis_result` is equal to 1, indicating that the data in the pickled object is safe. If `analysis_result` is 1, we can exit the function and print the cleaned data if needed.

If `analysis_result` is not 1, we move on to the next step, which is to check if the pickled object contains malicious data using the `scann()` function. If `scann()` finds malicious data, the function exits and prints that the data is not clean and the file is not fixed. If `scann()` does not find any malicious data, we move on to the next step.

The next step is to perform a CDR check and fix any remaining malicious data in the pickled object. If the CDR check finds and fixes any malicious data, we move on to the next step. If the CDR check does not find any malicious data, the function exits and prints that the data is not clean and the file is not fixed.

Finally, we perform the `analysis.check_safety()` function on the pickled object again and check if `analysis_result_2` is equal to 1. If `analysis_result_2` is 1, we exit the function and print the cleaned data if needed. If `analysis_result_2` is not 1, the function exits and prints that the data is not clean and the file is not fixed.

At the end of the Disarm Flow, we reach the end of the function and the end of the Control Flow Graph.
