# Final-project-in-Cyber-Security-MoudleGuard
# ModelGuard: Ransomware Protection Initiative
## written by ✨

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/RazElbaz"><img src="https://avatars.githubusercontent.com/u/93310416?v=4" width="100px;" alt="Raz Elbaz"/><br /><sub><b>Raz Elbaz</b></sub></a><br /><a href="https://github.com/RazElbaz" title="Code">💻</a> <br /> </td>
  </tr>
</table>
## The instructors of the project

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><img src="(https://dir.co.il/wp-content/uploads/2023/02/DR_RAN_DUBIN_ORIG-1.jpg)" width="100px;" alt="Dr. Ran Dubin"/><b>Dr. Ran Dubin</b></sub></a><br /> </td>
    <td align="center"><img src="(https://www.ariel.ac.il/Projects/tzmm/Uploads/TRPUserImages/3750b467b8674c08514c8bf14b93a93b.jpg)" width="100px;"/><br /><sub><b>Dr. Ran Dubin</b></sub></a><br /> 
    <td align="center"><img src="(https://www.ariel.ac.il/Projects/tzmm/Uploads/TRPUserImages/3750b467b8674c08514c8bf14b93a93b.jpg)" width="100px;" alt="Prof. Amit Dvir"/><br /><sub><b>Prof. Amit Dvir</b></sub></a><br /> </td>

  </tr>
</table>

## Project Goal:
The goal of the project is to develop a comprehensive framework and implement advanced security measures to protect models from ransomware attacks, including those that hide in executable code or exploit vulnerabilities in metadata.

## Introduction:
The ModelGuard: Ransomware Protection Initiative focuses on mitigating the growing threat of ransomware attacks targeting models. Our goal is to develop the ModelGuard framework, a comprehensive solution that safeguards models from malicious code and metadata-based attacks. Through this initiative, we aim to ensure the integrity and availability of models, protecting them from evolving ransomware threats.
Methods/algorithms/Alternatives or Design Considerations:
To achieve protection against ransomware attacks, our project focuses on the following approaches:
1.	Vulnerability identification: Thoroughly research and identify potential vulnerabilities specific to the models, focusing on those exploitable in ransomware attacks.
2.	Attack simulation: Simulate various attack scenarios to locate and identify vulnerabilities within the models effectively.
3.	Cleanup mechanism: Develop a robust mechanism to remove the malicious code from infected models, ensuring that only the clean portion of the files remains intact while removing any malicious components.
## Selected Approach:
•	Use of secure serialization libraries to prevent code execution vulnerabilities.
•	Implementing input sanitization and data validation techniques for maintaining data integrity.
•	Promoting custom deserialization methods to mitigate the risk of arbitrary code execution.
•	Applying input filtering and whitelisting mechanisms to reduce the likelihood of malicious data.
•	Conducting regular security audits to identify and address vulnerabilities in serialization and deserialization processes.
## Solution Description:
The project aims to protect models from ransomware attacks through a comprehensive framework and advanced security measures. The solution includes algorithms for detecting and removing malicious code, as well as identifying and mitigating ransomware threats. It adopts modular design principles, leveraging established security patterns. The infrastructure ensures secure storage, retrieval, and execution of models. The user interface facilitates model loading, vulnerability scanning, and monitoring of security status. The key functionalities include secure model loading, vulnerability scanning, malicious code detection, ransomware detection, model cleaning, and real-time monitoring. Overall, the solution provides a secure environment for deploying and executing models, protecting against ransomware attacks that can exploit models capable of running hostile code or hiding in metadata.

# Code: 
The project includes several scripts:
## Task 1
Learn about a pickle file: what it is, how to attack it. Execute an attack - I implemented a malicious pickle creation, I implemented sender and receiver programs to implement an attack that activates a code that runs automatically on the receiver and performs an attack.

The sender.py and receiverpy programs send a pickle file from the sender to the receiver, the receiver loads the information received from the sender and receives a list of passwords.

In the program `Pickle_Arbitrary_Code_Execution.py` there is a display of information output (can also be applied in sending with socket) such as passwords from the computer, groups, hosts and PAM.

In the program maliciousPickle.py there is a creation of a normal pickle file into which data was pushed and if we execute the following commands: cat payload.pkl, hexyl `payload.pkl` we can see the data that was pushed
## Task 2 
`maliciousPickle.py`
Develop a code that statically reads the pickle file and scans the active parts in it.
## Task 3
Removing malware from a pickle file
`MaliciousExtraction.py`

## Task 4
The task is to modify the pickle package by removing parts that could be used for malicious attacks, add a new capability called cdr.py, and then test that this change works by running parse and cdr, and verifying that parse returns "clean" after cdr is called. I need to remove the parts that can cause an attack because a pickle has parts that make it explosive

`cdr.py`
`test.py` -This file is more pickle files - some are clean and some are malicious, the code will load the pickle file in a protected form, analyze it with fickling.analysis, if there is anything malicious in it, the code will run cdr.py which will remove the malware from it and return a clean file to the user.

## Task 5
1. Produce one file that accepts the type of attack and produces a suitable attacked pickle with. cmd. -> attack_cmd.py
**To run:** python `attack_cmd.py [attack_type]`
`python attack_cmd.py -h` -> to get help with attack_type arguments

2. Produce one file that accepts the type of attack and produces a suitable attacked pickle with. cmd. and then removes with cdr the malicious part in the pickle file -> cdr_cmd.py
**To run:** `python cdr_cmd.py [attack_type]`

## Task 6
There is an unreal ransomware scam written on dotnet
https://github.com/araujo88/S4VEtheD4TE
The goal is to create an exe and link it to the attack
To activate:
1. for the file: install .net core version 3.1 (exactly) and visual studio -2019
2. create a folder `encryption_test` ion drive `c:\`
add file you do not need - they will be encrypted

The idea is to run the attack that will execute the exe file and once it will execute you will see a ransom note.

In the folder attack_exe_file there is the compiled library-> you can download directly but be careful it contains malicious ♥ Download the folder to the VM

## Task 7
Creating a jupyter that extracts features from pickle files and creates a prediction

## Task 8
There is an unreal ransomware scam written on dotnet  
https://github.com/araujo88/S4VEtheD4TE  
The goal is to create an exe and link it to the attack  
To activate:
1. for the file: install .net core version 3.1 (exactly) and visual studio -2019
2. create a folder "encryption_tests" ion drive c:\
add file you do not need - they will be encrypted

The idea is to run the attack that will execute the exe file and once it will execute you will see a ransom note.

In the folder attack_exe_file there is the compiled library-> you can download directly but be careful it contains malicious ♥ Download the folder to the VM


`PickleCDR.ipynb`: Creating a model that contains an exe file that triggers a ransomware attack.
Loading the model without a protected path and without the cdr.py written library led to an attack.
The pickle file is then loaded in protected form -> using the directory ficking.pickle import Pickled
It can be seen that the attack is not activated.
The program runs cdr.py removes the malware, and shows the "clean" data that was in the file.
Now you can load the pickle file in the protected way, and in the unprotected way -> in both ways the ransomware attack will not be activated.


`attack_exe_file.zip` :  The compiled library-> you can download directly but be careful it contains malicious 

`pickleCDR.mp4` : Video of running jupyter notebook

## Pickle file  

The pickle module in Python provides functions for serializing and deserializing Python objects into a binary format. The module defines two main classes: Pickler and Unpickler, which are used to serialize and deserialize Python objects, respectively.

The Pickler class is used to convert a Python object into a byte stream, while the Unpickler class is used to convert a byte stream back into a Python object.


## How to Run:
Go to code/task5  
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

9. `safe_os.pkl`: This pickle file contains a safe `Os` object that, when unpickled, executes the code `"echo 'I execute code that runs on your computer'"` using the `system()` function from the `os` module. This is not a malicious attack.  

10. `unsafe.pkl`: This pickle file contains a maliciously crafted `Pickled` object that, when unpickled, executes several lines of code, including `with open('/etc/passwd','r') as r: print(r.readlines())`, `with open('/etc/group','r') as r: print(r.readlines())`, and `os.system('echo Malicious code!')`. This can be used to read sensitive files and execute arbitrary code on the target machine.  
The file `unsafe.pkl` is dangerous because it contains malicious code that can be executed when the file is loaded using the `pickle` module. 
The code creates a list of student names and then pickles it using the `pickle.dumps()` method. It then loads the pickled object into a `Pickled` object and inserts four different lines of malicious code using the `insert_python_exec()` method. 
The first two lines of malicious code open and read the `/etc/passwd` and `/etc/group` files, which can be a serious security risk as these files contain sensitive information about users and groups on the system. 
The third line of code imports a module named `module` and prints the string "malicious". This may seem harmless, but importing unknown modules can be a security risk as the module could contain malicious code. 
The fourth line of code uses the `os.system()` method to execute the shell command "echo Malicious code!", which can be a serious security risk as it allows arbitrary code execution on the system. 
When the pickled object is loaded and unpickled using the `pickle.load()` method, the malicious code will be executed, potentially causing serious harm to the system. Therefore, it is important to be careful when loading pickled objects from untrusted sources and to only load pickled objects that come from trusted sources.
## In general for all attacks:

## malicious_exec
This code shows an example of a subattack that exploits Python's pickle module to execute arbitrary code. The `ExecuteCode` class defines a custom serialization method that will execute arbitrary code when an object of this class is deserialized using the `pickle.load()` method. This is achieved by returning a tuple with the `builtins.exec()` function as the first element and a string that contains the code to be executed as the second element.

The attacker then creates a pickled object that contains an instance of the `ExecuteCode` class and a list called `my_list`, and saves it to a file called `malicious_exec.pkl`. This file can be used to attack a system that unpickles arbitrary data from an untrusted source.

The `mal_exec()` function simulates the scenario where the attacker's pickled object is loaded from the `malicious_exec.pkl` file and checks if the object is safe to unpickle by calling the `analysis.check_safety()` function. If the object is considered safe, the function prints "clean". Otherwise, it calls the `scan_pickle_file.scann()` function to scan the file for malicious data and removes any malicious code using the `cdr.check_safety()` function. Finally, the function checks again if the pickled object is safe to unpickle by calling the `analysis.check_safety()` function and prints "clean" if it is safe, or "not clean" if it still contains malicious data.

To defend against this type of attack, it's important to avoid unpickling data from untrusted sources and to use serialization libraries that are designed with security in mind. Additionally, it's recommended to sanitize user input and validate data before serialization and deserialization.  
**Attack Flow:**

```
                                      +-----------------------+
                                      | Print function name    |
                                      | and separator         |
                                      +-----------------------+
                                                 |
                                                 v
                                  +------------------------------+
                 mal_exec() ->   | Load malicious pickle file   |
                                  | from storage                 |
                                  +------------------------------+
                                                 |
                                                 v
                                  +------------------------------+
                                  | Check safety of pickled obj  |
                                  +------------------------------+
                                                 |
                                  +---------------+-------------+
                                  |               |             |
                                  v               v             v
                       +---------------------+    |    +---------------------+
                       | Object is safe       |   |    | Object is not safe   |
                       +---------------------+    |    +---------------------+
                                                  |              |
                                                  v              |
                                  +------------------------------+
                                  | Load and scan pickle file for |
                                  |  malicious data removal      |
                                  +------------------------------+
                                                 |
                                                 v
                                  +------------------------------+
                                  | Load and check pickle file for|
                                  |  cleaned object               |
                                  +------------------------------+
                                                  |
                                  +---------------+-------------+
                                  |               |             |
                                  v               v             v
                    +-----------------------+    |    +------------------------+
                    | Object is safe         |   |    | Object is not safe      |
                    +-----------------------+    |    +------------------------+
                                                 |               |
                                                 v               |
                                  +------------------------------+
                                  | Check safety of cleaned obj   |
                                  +------------------------------+
                                                  |
                                  +---------------+-------------+
                                  |               |             |
                                  v               v             v
                     +----------------------+     |    +------------------------+
                     | Cleaned object is    |     |    | Cleaned object is not    |
                     | safe                 |     |    | safe                     |
                     +----------------------+     |    +------------------------+
                                                  |               |
                                                  v               |
                                    +------------------------------+
                                    | Print clean data from pickle  |
                                    | file                          |
                                    +------------------------------+


 ```

1. The attacker defines a class called `ExecuteCode` with a `__reduce__` method that executes arbitrary code when the class is pickled and unpickled.

2. The attacker then creates a malicious pickle file `malicious_exec.pkl` containing an instance of `ExecuteCode` class and some other data (`my_list`), using the `pickle.dump` method.

3. The attacker then runs the `mal_exec` function, which loads the pickle file, checks its safety using `analysis.check_safety`, and if it is deemed safe, prints "clean" and exits. However, if the pickle file is deemed unsafe, the function performs several actions to attempt to clean the file and make it safe:

   - It calls `scan_pickle_file.scann` to scan the file for malicious data.
   
   - It calls `cdr.check_safety` to remove the malicious data from the file and check if the resulting file is safe.
   
   - It checks the safety of the file again using `analysis.check_safety` to confirm that the file is now safe.
   
4. If the pickle file is now safe, the function prints "clean" and the clean data left in the file. If the file is still deemed unsafe, the function prints "not clean".  

**Disarm Flow:**




```
                +---------------+
                |   Load pickle |
                |    from file  |
                +---------------+
                          |
                          v
                +---------------+
                | Check safety  |
                |   of object   |
                +---------------+
                          |
               +--------------+--------------+
               |                             |
               v                             v
   +-------------------+         +-------------------+
   |  Object is safe    |         |  Object is not safe|
   |                   |         |                   |
   +-------------------+         +-------------------+
                          |                   |
                          v                   v
                +---------------+    +----------------------+
                |   Load pickle |    | Remove malicious data |
                |    from file  |    |  from object           |
                +---------------+    +----------------------+
                          |                   |
                          v                   v
                +---------------+    +----------------------+
                | Check safety  |    |  Load cleaned pickle   |
                |  of cleaned   |    |  from file             |
                |     object    |    +----------------------+
                +---------------+                |
                          |                      v
                          |          +----------------------+
                          +--------> | Check safety of object |
                                     +----------------------+



```

1. The attacker defines the `ExecuteCode` class with the `__reduce__` method that calls `builtins.exec` with the arbitrary command as a string argument.
2. The attacker serializes an instance of `ExecuteCode` class with some data to create the pickle.
3. The attacker saves the pickle in a file named `malicious_exec.pkl`.
4. The attacker calls the `mal_exec()` function.
5. The function opens the `malicious_exec.pkl` file, reads the pickled data, and unpickles it into a Python object.
6. The function runs the `check_safety` function of the `analysis` module to check if the unpickled object is safe.
7. If the object is safe, the function prints "clean" and stops.
8. If the object is not safe, the function calls the `scann` function of the `scan_pickle_file` module to remove any malicious code from the pickled object.
9. The function then runs the `check_safety` function of the `cdr` module to verify that the pickled object is now safe.
10. If the pickled object is safe, the function prints "clean" and stops.
11. If the pickled object is not safe, the function prints "not clean" and stops.

## malicious_socket
**Attack Flow:**
```
    .--------------------.                          .---------------------.
    |                    |                          |                      |
    |  MalSocket object  |         2. Pickle        |  malicious_socket.pkl|
    |                    | <-----------------------  |                     |
    '--------------------'                          '---------------------'
             |                                                   |
             |                                                   |
             v                                                   v
    .--------------------.                          .---------------------.
    |                    |                          |                     |
    |   malicious_socket |         4. Load          |   unpickled object  |
    |      function      | <----------------------- |     from file       |
    |                    |                          |                     |
    '--------------------'                          '---------------------'
             |                                                   |
             |                      5. Check safety              |
             v                                                   v
    .--------------------.                         .---------------------.
    |                    |                         |                     |
    |   analysis.check   |       6. True: print    |    "Clean" message  |
    |       safety       | <-----------------------|                     |
    |                    |                         |                     |
    '--------------------'                         '---------------------'
             |                                                   |
             |                      7. False: scan file           |
             v                                                   v
    .--------------------.                          .---------------------.
    |                    |                          |                     |
    |  scan_pickle_file  |                          |      cdr.check      |
    |                    |                          |        safety       |
    |        scann       |                          |                     |
    |                    |                          |                     |
    '--------------------'                          '---------------------'
             |                                                   |
             |                                                   |
             v                                                   v
    .--------------------.                          .---------------------.
    |                    |                          |                     |
    | cdr.check_safety() |                          |analysis.check_safety|
    |                    |                          |                     |
    '--------------------'                          '---------------------'
             |                                                   |
             |                                                   |
             v                                                   v
    .--------------------.                          .---------------------.
    |                    |                          |                     |
    |                    |                          |    "Clean" message  |
    |     Not Clean      |                          |   and clean data    |
    |     message        |                          |                     |
    |                    |                          |                     |
    '--------------------'                          '---------------------'
```
1. The attacker creates a malicious socket object using the MalSocket class and pickles it.
2. The attacker saves the pickled object in a file named malicious_socket.pkl.
3. The attacker runs the malicious_socket() function.
4. The function loads the pickled object from the malicious_socket.pkl file.
5. The function runs analysis.check_safety() on the pickled object.
6. If analysis.check_safety() returns True, the function prints "clean" and exits.
7. If analysis.check_safety() returns False, the function calls scan_pickle_file.scann() on the file name to scan for malicious content.
8. The function calls cdr.check_safety() on the pickled object to check for malicious content and remove it if found.
9. The function runs analysis.check_safety() on the pickled object again to check if it is clean.
10. If analysis.check_safety() returns True, the function prints "clean", displays the clean data, and exits.
11. If analysis.check_safety() returns False, the function prints "not clean" and exits.
```
                            +------------------+
                            |  Pickle File     |
                            +------------------+
                                      |
                                      v
           +--------------------------------------------------+
           |             Check for Malicious Content           |
           +--------------------------------------------------+
                        |            |            |
                        v            v            v
        +----------------------+     |  +----------------------+
        |  No Malicious Content|     |  |  Malicious Content    |
        |  Found               |     |  |  Found                |
        +----------------------+     |  +----------------------+
                                     |
                                     v
                      +------------------------------------+
                      |          Remove Malicious Content  |
                      +------------------------------------+
                                     |
                                     v
                              +---------------+
                              |   Cleaned     |
                              |   Pickle File |
                              +---------------+

```
:**Defense Flow::**
1. The defender uses a combination of input validation and data sanitation to prevent malicious data from being pickled and saved in a file.
2. The defender uses a whitelist to ensure that only valid objects can be pickled and loaded from a file.
3. The defender scans all files for malicious content before loading them.
4. The defender uses a combination of input validation and data sanitation to prevent malicious code from being executed during unpickling.
5. The defender checks for the presence of malicious content in the unpickled object using cdr.check_safety() and removes it if found.
6. The defender uses a combination of static analysis and dynamic testing to detect and prevent attacks during pickling and unpickling.
7. The defender educates developers and users on the risks of pickling and unpickling untrusted data and encourages them to use safer alternatives.


## malicious_eval  
**Attack Flow:**
The attack here involves pickling and dumping an instance of the `EvalCode` class into a file named `malicious_eval.pkl`. This class defines a `__reduce__` method which returns `eval` and the argument `("['a', 'b', 'c']",)` when called. This means that when the object is unpickled, the `eval` function will be called with the argument `("['a', 'b', 'c']",)`, which will execute arbitrary code in the context of the program.  


```
                                 +-----------------+
                                 |     Attacker    |
                                 +-----------------+
                                        |
                                        | creates
                                        |
                                        V
                                 +-----------------+
                                 |  EvalCode() obj |
                                 +-----------------+
                                        |
                                        | pickles into
                                        |
                                        V
                             +-----------------------+
                             | malicious_eval.pkl file |
                             +-----------------------+
                                        |
                                        | loads and unpickles
                                        |
                                        V
                                 +-----------------+
                                 |   Malicious     |
                                 |  code executed  |
                                 +-----------------+
                                        |
                                        |
                           +------------+------------+
                           |                         |
                           V                         V
            +-------------------------+   +-------------------------+
            |        Defense          |   |         Defense          |
            +-------------------------+   +-------------------------+
                                        |
                                        | runs analysis.check_safety()
                                        |
                                        V
                                 +-----------------+
                                 | Safe or not safe|
                                 +-----------------+
                                        |
                                        | if not safe, run
                                        |
                                        V
                                 +-----------------+
                                 | scan_pickle_file|
                                 +-----------------+
                                        |
                                        | inspect for malicious data
                                        |
                                        V
                                 +-----------------+
                                 |  cdr.check_safety|
                                 +-----------------+
                                        |
                                        | if clean, remove malicious code and run analysis.check_safety()
                                        V
                                 +-----------------+
                                 | Safe or not safe|
                                 +-----------------+
                                        |
                                        |
                           +------------+------------+
                           |                         |
                           V                         V
               +----------------------+   +-----------------------+
               | Load clean object    |   |   Object still not safe |
               | from malicious_eval.pkl|   |  Report and terminate   |
               +----------------------+   +-----------------------+
  ```  

1. An instance of `EvalCode` class is created and pickled into a file named `malicious_eval.pkl`.
2. The file is loaded and the pickled object is unpickled using `Pickled.load()` method.
3. The `check_safety()` method from the `analysis` module is called to check the safety of the unpickled object.
4. If the object is determined to be safe, the program exits.
5. If the object is determined to be unsafe, the `scann()` method from the `scan_pickle_file` module is called to scan the file for malicious data.
6. The `check_safety()` method from the `cdr` module is then called to clean the object of malicious code.
7. The file is loaded again and the pickled object is unpickled using `Pickled.load()` method.
8. The `check_safety()` method from the `analysis` module is called to check the safety of the unpickled object again.
9. If the object is determined to be safe, the program exits.
10. If the object is determined to be unsafe, the clean data left in the file is printed.   
**Defense flow:**
```
                                 +----------------+
                                 |  Input: Pickle |
                                 +--------+-------+
                                          |
                                 +--------v-------+
                                 | Check Safety   |
                                 +--------+-------+
                                          |
                                 +--------v-------+
                                 |  Is it safe?   |
                                 +--------+-------+
                                          |
                        +-------------+   |   +-------------+
                        |             |   |   |             |
                +-------v-------+ +---+---v-----+ +-------v-------+
                |  Clean Data   | |  Malicious  | |  Remove Mal.  |
                |  Left in File | |  Detected?  | |  Data         |
                +---------------+ +------------+ +---------------+
                                          |
                                 +--------v-------+
                                 |  Check Safety  |
                                 +--------+-------+
                                          |
                                 +--------v-------+
                                 |  Is it safe?   |
                                 +--------+-------+
                                          |
                                 +----------------+
                                 | Output: Results |
                                 +----------------+
```  
The flow of the disarm is as follows:
1. The `check_safety()` method from the `cdr` module is called to clean the object of malicious code.
2. The file is loaded again and the pickled object is unpickled using `Pickled.load()` method.
3. The `check_safety()` method from the `analysis` module is called to check the safety of the unpickled object again.
4. If the object is determined to be safe, the program exits.
5. If the object is determined to be unsafe, the clean data left in the file is printed.

## malicious_compile
**Attack Flow:**  
```
                                      +------------------------+
                                      |        mal_compile      |
                                      +------------------------+
                                                 |
                                                 |
                                                 v
                      +----------------------------------------------------+
                      |       Read the malicious pickle file into memory    |
                      +----------------------------------------------------+
                                                 |
                                                 |
                                                 v
                +-------------------------------------------------------+
                |          Run analysis to check if the data is safe       |
                +-------------------------------------------------------+
                                                 |
                                                 |
                                                 v
                                  +------------------------+
                                  |   If data is not safe:   |
                                  +------------------------+
                                                 |
                                                 |
                                                 v
                   +--------------------------------------------------+
                   |      Run scan_pickle_file to remove the data      |
                   +--------------------------------------------------+
                                                 |
                                                 |
                                                 v
                 +------------------------------------------------------+
                 |   Check data again with cdr.check_safety() function   |
                 +------------------------------------------------------+
                                                 |
                                                 |
                                                 v
                 +--------------------------------------------------------+
                 |    Read the cleaned data into memory and check again   |
                 +--------------------------------------------------------+
                                                 |
                                                 |
                                                 v
                                   +-------------------------+
                                   |  If data is clean:       |
                                   |  Print the clean data    |
                                   |  Otherwise, print error  |
                                   +-------------------------+
```

1. A `CompileCode` class is defined that contains a `__reduce__` method that returns a `compile` function with the string "print('I execute code that runs on your computer')" as its first argument.
2. The `CompileCode` instance is pickled and saved to a file called `malicious_compile.pkl`.
3. The `mal_compile` function loads the pickled object from the file, runs an initial safety check using the `analysis.check_safety` function, and prints the analysis result.
4. If the analysis result is false, indicating that the pickled object is malicious, the `scan_pickle_file.scann` function is called to scan the file for malicious code.
5. The `cdr.check_safety` function is called to remove the malicious code from the pickled object, and the result is printed.
6. The pickled object is loaded from the file again, and a final safety check is performed using `analysis.check_safety` function, and the result is printed.  
```
                             +--------------------------------------------------------+
                             |               Defense Flow Against mal_compile()       |
                             +--------------------------------------------------------+
                                                           |
                                                           |
                                            +--------------v---------------+
                                            | Check for malicious function |
                                            +--------------+---------------+
                                                           |
                                                           |
                                           /---------------+---------------\
                                          /                                 \
                   +--------------------v--+                                +---------------------+
                   | If function is clean |                                | If function is dirty |
                   +--------------------+                                +---------------------+
                                                           |                               |
                                                           |                               |
                                           /---------------+---------------\               |
                                          /                                 \              |
                  +--------------------v--+                                |               |
                  | Check pickle contents |                                |               |
                  +---------------------+                                |                 |
                                                           |                |              |
                                                           |                |              |
                                           /---------------+---------------\               |
                                          /                                 \              |
                 +---------------------v--+                                 |              |
                 | Check CDR for threats  |                                 |              |
                 +---------------------+                                 |                 |
                                                           |                |              |
                                                           |                |              |
                                           /---------------+---------------\               |
                                          /                                 \              |
                        +---------------v---+                                 |            |
                        | Check pickle again|                                 |            |
                        +---------------+---+                                 |            |
                                           |                                  |            |
                                           |                                  |            |
                        /------------------+                                  |            |
                       /                                                      |            |
          +---------v----------+                                              |            |
          | If pickle is clean |                                              |            |
          +--------------------+                                              |            |
                               |                                              |            |
                               |                                              |            |
                +--------------v---------------+                              |            |
                | Open pickle and load object |                               |            |
                +--------------+---------------+                               |           |
                               |                                                |          |
                               |                                                 |         |
                /--------------+---------------\                                  |        |
               /                                \                                 |        |
+---------v----+                          +-----+------+                           |       |
| Print "Clean" |                          | Remove CDR |                           |      |
+--------------+                          +-----------+                               |    |
                                                                                        |
                                                                                        |
                                                                         +--------------v--------------+
                                                                         | Print "Not Clean" and exit |
                                                                         +--------------+--------------+
                                                                                        |
                                                                                        |
                                                                         +--------------v--------------+
                                                                         | Delete pickle file and exit |
                                                                         +----------------------------+
```
**Defense flow:**
1. The `cdr.check_safety` function removes the malicious code from the pickled object and returns the cleaned object. 
2. The cleaned pickled object is saved to the file and returned. 
3. The `analysis.check_safety` function is called on the cleaned object, and if it returns true, indicating that the object is safe, then the disarm process is considered complete.


## malicious_Pickled
**Attack Flow:**
```
              +------------------------------------+
              |         Initial State               |
              +------------------------------------+
                              |
                              V
                +----------------------------------+
                |      pickle.dumps(student_names) |
                +----------------------------------+
                              |
                              V
               +----------------------------------+
               |       Pickled.load(pickle_bin)  |
               +----------------------------------+
                            |
                            V
   +----------------------------------------------------------------------------------+
   |  p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())") |
   +----------------------------------------------------------------------------------+
                            |
                            V
   +--------------------------------------------------------------------------------+
   |  p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())") |
   +--------------------------------------------------------------------------------+
                            |
                            V
       +----------------------------------------------------------+
       |  p.insert_python_exec("import module print('malicious')") |
       +----------------------------------------------------------+
                            |
                            V
   +-----------------------------------------------------------------------+
   |  p.insert_python_exec("import os  os.system('echo Malicious code!')") |
   +-----------------------------------------------------------------------+
                            |
                            V
     +-------------------------------------------------+
     |       p.dump(f) (Writing to unsafe.pkl file)    |
     +-------------------------------------------------+
                            |
                            V
             +-------------------------------+
             |     End of Attack Flow       |
             +-------------------------------+


```


1. Creates a list of student names.
2. Pickles the list and stores it in a file named "unsafe.pkl".
3. Uses the Pickled.load() method to load the pickled data from the file.
4. Calls the insert_python_exec() method of the Pickled object to insert the following malicious code snippets:
   * with open('/etc/passwd','r') as r: print(r.readlines())
   * with open('/etc/group','r') as r: print(r.readlines())
   * import module print('malicious')
   * import os  os.system('echo Malicious code!')
5. Dumps the modified Pickled object to the same file.




**Defense Flow:**
```
              +------------------------------------+
              |     Initial State (unsafe.pkl)     |
              +------------------------------------+
                            |
                            V
   +------------------------------------------------------+
   |       pickled_data = f.read() (Read unsafe.pkl file)   |
   +------------------------------------------------------+
                            |
                            V
+------------------------------------------------------+
| pickled_obj = Pickled.load(pickled_data) (Load pickled object) |
+------------------------------------------------------+
                            |
                            V
    +-----------------------------------------------------+
    | analysis_result = analysis.check_safety(pickled_obj) |
    +-----------------------------------------------------+
                            |
                            V
                +-----------------------+
                |   If analysis_result  |
                |       is True          |
                +-----------------------+
                            |
                            V
                      Clean Data
                            |
                            V
             +-------------------------------+
             |   End of Disarm Flow         |
             +-------------------------------+


```




1. The `mal_Pickled()` function is called.
2. The file 'unsafe.pkl' is read and its contents are stored in the `pickled_data` variable.
3. The `Pickled.load()` method is used to load the pickled data into a `pickled_obj` variable.
4. The `analysis.check_safety()` function is called to perform an analysis on the loaded pickled object and the result is stored in the `analysis_result` variable.
5. If the `analysis_result` is `True`, it means the data is considered clean, and the program prints "clean".
6. If the `analysis_result` is `False`, it means the data is considered not clean. The program proceeds to perform the following steps:
   - The `scan_pickle_file.scann()` function is called to scan the 'unsafe.pkl' file for malicious data.
   - The program prints "Now removing the malicious data...."
   - The `cdr.check_safety()` function is called to check the safety of the `pickled_obj` and the filename.
   - The `analysis.check_safety()` function is called again on the reloaded pickled data, and the result is stored in `analysis_result_2`.
7. If `analysis_result_2` is `True`, it means the data is considered clean after the removal of malicious content. The program prints "clean" and displays the remaining clean data in the file.
8. If `analysis_result_2` is `False`, it means the data is still considered not clean. The program prints "not clean" and does not display the remaining data.
## malicious_open
**Attack flow:**
```
  +-----------------------+
  |      Attack Flow       |
  +-----------------------+
              |
              V
   +----------------------+
   |    Malicious Object   |
   +----------------------+
              |
              V
+------------------------------------+
|   Dump Malicious Object to File    |
+------------------------------------+
              |
              V
   +----------------------+
   |  Load Pickled Object  |
   +----------------------+
              |
              V
   +----------------------+
   |   Check Analysis 1    |
   +----------------------+
       |         |
      /           \
     /             \
    V               V
+----------+    +-----------+
| Clean    |    | Not Clean |
+----------+    +-----------+
     |               |
     V               V
+------------------------+
|  Scan for Malicious Data|
+------------------------+
     |               |
     V               V
+--------------------------+
| Check Controlled Data Run |
+--------------------------+
     |               |
     V               V
+----------------------+
|   Check Analysis 2    |
+----------------------+
       |         |
      /           \
     /             \
    V               V
+----------+    +-----------+
| Clean    |    | Not Clean |
+----------+    +-----------+
     |               |
     V               V
+----------------------+
|   Return Clean Data   |
+----------------------+
     |               |
     V               V
+----------------------+
|  Print Clean Data     |
+----------------------+

```
1. The attacker creates a class called "OpenFile" that contains a malicious payload to open the "/etc/passwd" file.
2. The attacker pickles the "OpenFile" object and saves it to a file called "malicious_open.pkl".
3. The attacker distributes the "malicious_open.pkl" file to the target system.

**Defense flow:**
```
  +-----------------------------+
  |         Disarm Flow         |
  +-----------------------------+
                  |
                  V
        +----------------+
        | Check analysis |
        +----------------+
                  |
                  V
        +----------------+
        |     Cleanup     |
        +----------------+
                  |
                  V
+---------------------------------+
| Check CDR (Controlled Data Run) |
+---------------------------------+
                  |
                  V
         +--------------+
         | Check analysis|
         +--------------+
                  |
                  V
        +-----------------+
        | Return clean data|
        +-----------------+
                  |
                  V
        +-----------------+
        | Print clean data|
        +-----------------+


```
1. The "mal_open()" function is called.
2. The function loads the pickled data from the "malicious_open.pkl" file and unpickles it into an object.
3. The "check_safety()" function from the "analysis" module is called to analyze the object and determine if it is safe.
4. If the object is determined to be safe, the program proceeds as usual and prints "clean".
5. If the object is determined to be malicious, the "scann()" function from the "scan_pickle_file" module is called to scan the file for malware.
6. The "check_safety()" function from the "cdr" module is called to check if the object is safe after removing the malicious payload.
7. If the object is determined to be safe, the program proceeds and prints "clean" and the clean data is printed.
8. If the object is still determined to be malicious, the program prints "not clean".


