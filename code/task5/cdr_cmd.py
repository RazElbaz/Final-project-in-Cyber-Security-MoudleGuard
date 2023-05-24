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
def setUpClass():
        class ExecuteCode(object):
            def __reduce__(self):
                return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
        class EvalCode(object):
            def __reduce__(self):
                return (eval, ("['a', 'b', 'c']",))
        class CompileCode(object):
            def __reduce__(self):
                return (compile, ("print('I execute code that runs on your computer')", "<string>", "exec"),)
        class OpenFile(object):
            def __reduce__(self):
                return (builtins.exec, ("f = open('/etc/passwd', 'r'); print(f.read()); f.close()",))
        class Os(object):
            def __reduce__(self):
                import os
                return (os.system, ("echo 'I execute code that runs on your computer'",))
        class MalSocket(object):
            def __reduce__(self):
                return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)

        if os.path.exists(
                'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_socket.pkl'):
            os.remove(
                'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_socket.pkl')
        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_socket.pkl', 'wb') as f:
            pickle.dump(MalSocket(), f)

        my_list = ['a', 'b', 'c']
        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_exec.pkl', 'wb') as f:
            pickle.dump((ExecuteCode(), my_list), f)

        student_names = ['Alice','Bob','Elena','Jane','Kyle']
        with open('student_file.pkl', 'wb') as f:  # open a text file
            pickle.dump(student_names, f) # serialize the list

        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_eval.pkl', 'wb') as f:
            pickle.dump(EvalCode(), f)

        with open(
                'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_compile.pkl', 'wb') as f:
            pickle.dump(CompileCode(), f)

        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_open.pkl', 'wb') as f:
            pickle.dump(OpenFile(), f)

        # create a list to pickle
        fruits = ['apple', 'banana', 'orange']
        # open a file in write binary mode to pickle
        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/fruits.pkl', 'wb') as f:
            # pickle the list
            pickle.dump(fruits, f)

        # create a dictionary to pickle
        person = {'name': 'John', 'age': 30, 'city': 'New York'}
        # open a file in write binary mode to pickle
        with open(
                'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/person_dictionary.pkl', 'wb') as f:
            # pickle the dictionary
            pickle.dump(person, f)
        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/safe_os.pkl', 'wb') as f:
            pickle.dump(Os(), f)

        # Create a malicious pickle
        student_names = ['Alice','Bob','Elena','Jane','Kyle']
        pickle_bin = pickle.dumps(student_names)
        p = Pickled.load(pickle_bin)
        p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
        p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
        p.insert_python_exec("import module print('malicious')")
        p.insert_python_exec("import os  os.system('echo Malicious code!')")

        with open('pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/unsafe.pkl', 'wb') as f:
            p.dump(f)


def mal_exec():
        print("--------------------------mal_exec----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_exec.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result) #Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2) #Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

def mal_Pickled():
        print("-----------------------mal_Pickled-------------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/unsafe.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
                # print(cdr.check_safety())

def mal_compile():
        print("-----------------------mal_compile-------------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_compile.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
                # print(cdr.check_safety())
def mal_open():
        print("-------------------------mal_open-----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_open.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

def mal_eval():
        print("--------------------------malicious_eval----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_eval.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

def malicious_socket():
        print("--------------------------malicious_socket----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/malicious_socket.pkl'
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
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
def safe_student_file():
        print("--------------------------safe-student_file----------------------------------")
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
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
def safe_fruits():
            print("--------------------------safe-fruits----------------------------------")
            with patch('sys.stdout') as stdout:
                filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/fruits.pkl'
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                # First run analysis.py
                analysis_result = analysis.check_safety(pickled_obj)
                print(analysis_result)
            if analysis_result == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
                scan_pickle_file.scann(filename)
                print("Now removing the malicious data....")
                with patch('sys.stdout') as stdout:
                    cdr_result = cdr.check_safety(pickled_obj,filename)
                    print(cdr_result)

                    # Finally, run analysis.py again
                    with open(filename, 'rb') as f:
                        pickled_data = f.read()
                    pickled_obj = Pickled.load(pickled_data)
                    analysis_result_2 = analysis.check_safety(pickled_obj)
                    print(analysis_result_2)
                # Check stdout for expected messages
                if analysis_result_2 == True:
                    print("clean")
                    print("\nThe clean data left in the file:")
                    with open(filename, 'rb') as f:
                        pickled_data = pickle.load(f)
                    print(pickled_data)
                else:
                    print("not clean")
def safe_person_dictionary():
        print("--------------------------safe-person_dictionary----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/person_dictionary.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
def safe_os():
        print("--------------------------safe_os----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'pkl-files (can be created with create_mal_pkl.py and create_safe_pkl.py)/safe_os.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            print(analysis_result)
        if analysis_result == True:
            print("clean")
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            scan_pickle_file.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                print(cdr_result)

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                print(analysis_result_2)
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                print("\nThe clean data left in the file:")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
# setUpClass()
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

# python attack_pickle.py [attack_type]
if __name__ == "__main__":
    setUpClass()
    if len(sys.argv) != 2:
        print("Usage: python attack_cmd.py [attack_type]")
        sys.exit(1)

    attack_type = sys.argv[1]

    if attack_type == "mal_exec":
        mal_exec()
    elif attack_type == "mal_Pickled":
        mal_Pickled()
    elif attack_type == "mal_compile":
        mal_compile()
    elif attack_type == "mal_open":
        mal_open()
    elif attack_type == "mal_eval":
        mal_eval()
    elif attack_type == "malicious_socket":
        malicious_socket()
    elif attack_type == "safe_student_file":
        safe_student_file()
    elif attack_type == "safe_fruits":
        safe_fruits()
    elif attack_type == "safe_person_dictionary":
        safe_person_dictionary()
    elif attack_type == "safe_os":
        safe_os()
    else:
        print("Invalid attack type.")
