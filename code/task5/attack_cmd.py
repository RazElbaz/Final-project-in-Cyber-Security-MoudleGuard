import argparse
import builtins
import os
import pickle
import socket
import sys
from unittest.mock import patch
import fickling.analysis as analysis
from fickling.pickle import Pickled
from termcolor import colored
def mal_exec():
        print("--------------------------mal_exec----------------------------------")
        print(colored("Creates a malicious pickle file...\n", "red"))
        class ExecuteCode(object):
            def __reduce__(self):
                return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
        my_list = ['a', 'b', 'c']
        with open('malicious_exec.pkl', 'wb') as f:
            pickle.dump((ExecuteCode(), my_list), f)
        with patch('sys.stdout') as stdout:
            filename= 'malicious_exec.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result) #Expecting clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")


def mal_Pickled():
        print("-----------------------mal_Pickled-------------------------------------")
        print(colored("Creates a malicious pickle file...\n", "red"))
        # Create a malicious pickle
        student_names = ['Alice','Bob','Elena','Jane','Kyle']
        pickle_bin = pickle.dumps(student_names)
        p = Pickled.load(pickle_bin)
        p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
        p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
        p.insert_python_exec("import module print('malicious')")
        p.insert_python_exec("import os  os.system('echo Malicious code!')")

        with open('unsafe.pkl', 'wb') as f:
            p.dump(f)
        with patch('sys.stdout') as stdout:
            filename= 'unsafe.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(Pickled.load(pickled_data))
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")



def mal_compile():
        print("-----------------------mal_compile-------------------------------------")
        print(colored("Creates a malicious pickle file...\n", "red"))
        class CompileCode(object):
            def __reduce__(self):
                return (compile, ("print('I execute code that runs on your computer')", "<string>", "exec"),)
        with open(
                'malicious_compile.pkl', 'wb') as f:
            pickle.dump(CompileCode(), f)
        with patch('sys.stdout') as stdout:
            filename= 'malicious_compile.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")


def mal_open():
        print("-------------------------mal_open-----------------------------------")
        print(colored("Creates a malicious pickle file...\n", "red"))
        class OpenFile(object):
            def __reduce__(self):
                return (builtins.exec, ("f = open('/etc/passwd', 'r'); print(f.read()); f.close()",))
        with open('malicious_open.pkl', 'wb') as f:
            pickle.dump(OpenFile(), f)

        with patch('sys.stdout') as stdout:
            filename= 'malicious_open.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")



def mal_eval():
        print("--------------------------malicious_eval----------------------------------")
        print(colored("Creates a malicious pickle file...\n", "red"))
        class EvalCode(object):
            def __reduce__(self):
                return (eval, ("['a', 'b', 'c']",))
        with open('malicious_eval.pkl', 'wb') as f:
            pickle.dump(EvalCode(), f)
        with patch('sys.stdout') as stdout:
            filename= 'malicious_eval.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")


def malicious_socket():
        print("--------------------------malicious_socket----------------------------------")

        class MalSocket(object):
            def __reduce__(self):
                 return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)
        print(colored("Creates a malicious pickle file...\n", "red"))
        if os.path.exists(
                'malicious_socket.pkl'):
            os.remove(
                'malicious_socket.pkl')
        with open('malicious_socket.pkl', 'wb') as f:
            pickle.dump(MalSocket(), f)
        with patch('sys.stdout') as stdout:
            filename= 'malicious_socket.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")


def safe_student_file():
        print("--------------------------safe-student_file----------------------------------")
        print(colored("Creates a new pickle file...\n", "green"))
        student_names = ['Alice','Bob','Elena','Jane','Kyle']
        with open('student_file.pkl', 'wb') as f:  # open a text file
            pickle.dump(student_names, f) # serialize the list
        with patch('sys.stdout') as stdout:
            filename='student_file.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")

        else:
            print("not clean")

def safe_fruits():
            print("--------------------------safe-fruits----------------------------------")
            print(colored("Creates a new pickle file...\n", "green"))
            # create a list to pickle
            fruits = ['apple', 'banana', 'orange']
            # open a file in write binary mode to pickle
            with open('fruits.pkl', 'wb') as f:
                # pickle the list
                pickle.dump(fruits, f)
            with patch('sys.stdout') as stdout:
                filename= 'fruits.pkl'
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                # First run analysis.py
                analysis_result = analysis.check_safety(pickled_obj)
                print(analysis_result)
            if analysis_result == True:
                print("clean")
            else:
                print("not clean")

def safe_person_dictionary():
        print("--------------------------safe-person_dictionary----------------------------------")
        print(colored("Creates a new pickle file...\n", "green"))
        # create a dictionary to pickle
        person = {'name': 'John', 'age': 30, 'city': 'New York'}
        # open a file in write binary mode to pickle
        with open(
                'person_dictionary.pkl', 'wb') as f:
            # pickle the dictionary
            pickle.dump(person, f)
        with patch('sys.stdout') as stdout:
            filename= 'person_dictionary.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")

def safe_os():
        print("--------------------------safe_os----------------------------------")
        print(colored("Creates a new pickle file...\n", "green"))
        class Os(object):
            def __reduce__(self):
                import os
                return (os.system, ("echo 'I execute code that runs on your computer'",))
        with open('safe_os.pkl', 'wb') as f:
            pickle.dump(Os(), f)
        with patch('sys.stdout') as stdout:
            filename= 'safe_os.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")

        else:
            print("not clean")


# mal_exec()
# mal_Pickled()
# mal_compile()
# mal_open()
# mal_eval()
# malicious_socket()
# safe_student_file()
# safe_fruits()
# safe_person_dictionary()
# safe_os()

# python attack_cmd.py [attack_type]
# Define the available attack types and their corresponding functions
attack_types = {
    "mal_exec": mal_exec,
    "mal_Pickled": mal_Pickled,
    "mal_compile": mal_compile,
    "mal_open": mal_open,
    "mal_eval": mal_eval,
    "malicious_socket": malicious_socket,
    "safe_student_file": safe_student_file,
    "safe_fruits": safe_fruits,
    "safe_person_dictionary": safe_person_dictionary,
    "safe_os": safe_os
}

def main():
    parser = argparse.ArgumentParser(description="Attack tool with Python's argparse")
    parser.add_argument("attack_type", choices=attack_types.keys(), help="Type of attack to execute")
    parser.add_argument("--file", help="Path to the file to be used in the attack")

    args = parser.parse_args()

    attack_type = args.attack_type
    attack_func = attack_types[attack_type]


    attack_func()

if __name__ == "__main__":
    main()

# import sys
# import argparse
#
# def setUpClass():
#     # Set up necessary configurations or resources for the attacks
#     pass
#
# def mal_exec(file_path):
#     # Implement mal_exec attack using the provided file
#     print(f"Executing mal_exec attack using file: {file_path}")
#     pass
#
# # Define the available attack types and their corresponding functions
# attack_types = {
#     "mal_exec": mal_exec,
#     # Add more attack types and their corresponding functions here
# }
#
# def main():
#     parser = argparse.ArgumentParser(description="Attack tool with Python's argparse")
#     parser.add_argument("attack_type", choices=attack_types.keys(), help="Type of attack to execute")
#     parser.add_argument("--file", help="Path to the file to be used in the attack")
#
#     args = parser.parse_args()
#
#     attack_type = args.attack_type
#     attack_func = attack_types[attack_type]
#
#     setUpClass()
#
#     if attack_type == "mal_exec":
#         file_path = args.file
#         if not file_path:
#             parser.error("The --file option is required for the mal_exec attack type.")
#         attack_func(file_path)
#
# if __name__ == "__main__":
#     main()
