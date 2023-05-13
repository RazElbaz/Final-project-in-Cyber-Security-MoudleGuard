import builtins
import os
import pickle
import socket
import sys
import unittest
from unittest.mock import patch
import fickling.analysis as analysis
from fickling.pickle import Pickled
import scan_pickle_file
import cdr

import unittest
from unittest.mock import patch
import fickling.analysis as analysis
from fickling.pickle import Pickled
# def setUpClass():
        # class ExecuteCode(object):
            # def __reduce__(self):
                # return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
        # class EvalCode(object):
        #     def __reduce__(self):
        #         return (eval, ("['a', 'b', 'c']",))
        # class CompileCode(object):
        #     def __reduce__(self):
        #         return (compile, ("print('I execute code that runs on your computer')", "<string>", "exec"),)
        # class OpenFile(object):
        #     def __reduce__(self):
        #         return (builtins.exec, ("f = open('/etc/passwd', 'r'); print(f.read()); f.close()",))
        # class Os(object):
        #     def __reduce__(self):
        #         import os
        #         return (os.system, ("echo 'I execute code that runs on your computer'",))
        # class MalSocket(object):
        #     def __reduce__(self):
        #         return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)
        #
        # if os.path.exists(
        #         'malicious_socket.pkl'):
        #     os.remove(
        #         'malicious_socket.pkl')
        # with open('malicious_socket.pkl', 'wb') as f:
        #     pickle.dump(MalSocket(), f)

        # my_list = ['a', 'b', 'c']
        # with open('malicious_exec.pkl', 'wb') as f:
        #     pickle.dump((ExecuteCode(), my_list), f)

        # student_names = ['Alice','Bob','Elena','Jane','Kyle']
        # with open('student_file.pkl', 'wb') as f:  # open a text file
        #     pickle.dump(student_names, f) # serialize the list

        # with open('malicious_eval.pkl', 'wb') as f:
        #     pickle.dump(EvalCode(), f)
        #
        # with open(
        #         'malicious_compile.pkl', 'wb') as f:
        #     pickle.dump(CompileCode(), f)

        # with open('malicious_open.pkl', 'wb') as f:
        #     pickle.dump(OpenFile(), f)

        # # create a list to pickle
        # fruits = ['apple', 'banana', 'orange']
        # # open a file in write binary mode to pickle
        # with open('fruits.pkl', 'wb') as f:
        #     # pickle the list
        #     pickle.dump(fruits, f)

        # # create a dictionary to pickle
        # person = {'name': 'John', 'age': 30, 'city': 'New York'}
        # # open a file in write binary mode to pickle
        # with open(
        #         'person_dictionary.pkl', 'wb') as f:
        #     # pickle the dictionary
        #     pickle.dump(person, f)
        # with open('safe_os.pkl', 'wb') as f:
        #     pickle.dump(Os(), f)

        # # Create a malicious pickle
        # student_names = ['Alice','Bob','Elena','Jane','Kyle']
        # pickle_bin = pickle.dumps(student_names)
        # p = Pickled.load(pickle_bin)
        # p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
        # p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
        # p.insert_python_exec("import module print('malicious')")
        # p.insert_python_exec("import os  os.system('echo Malicious code!')")
        #
        # with open('unsafe.pkl', 'wb') as f:
        #     p.dump(f)


def mal_exec():
        print("--------------------------mal_exec----------------------------------")
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
        class MalSocket(object):
            def __reduce__(self):
                 return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)
        print("--------------------------malicious_socket----------------------------------")
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

# setUpClass()
mal_exec()
mal_Pickled()
mal_compile()
mal_open()
mal_eval()
malicious_socket()
safe_student_file()
safe_fruits()
safe_person_dictionary()
safe_os()

# python attack_pickle.py [attack_type]
# if __name__ == "__main__":
#     setUpClass()
#     if len(sys.argv) != 2:
#         print("Usage: python attack_cmd.py [attack_type]")
#         sys.exit(1)
#
#     attack_type = sys.argv[1]
#
#     if attack_type == "mal_exec":
#         mal_exec()
#     elif attack_type == "mal_Pickled":
#         mal_Pickled()
#     elif attack_type == "mal_compile":
#         mal_compile()
#     elif attack_type == "mal_open":
#         mal_open()
#     elif attack_type == "mal_eval":
#         mal_eval()
#     elif attack_type == "malicious_socket":
#         malicious_socket()
#     elif attack_type == "safe_student_file":
#         safe_student_file()
#     elif attack_type == "safe_fruits":
#         safe_fruits()
#     elif attack_type == "safe_person_dictionary":
#         safe_person_dictionary()
#     elif attack_type == "safe_os":
#         safe_os()
#     else:
#         print("Invalid attack type.")
