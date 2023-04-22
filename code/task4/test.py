import builtins
import os
import pickle
import socket
import unittest
from unittest.mock import patch
import fickling.analysis as analysis
from fickling.pickle import Pickled
import MaliciousExtraction
import cdr

class TestSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class ExecuteCode(object):
            def __reduce__(self):
                return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
        class EvalCode(object):
            def __reduce__(self):
                return (eval, ("['a', 'b', 'c']",))
        class CompileCode(object):
            def __reduce__(self):
                return (compile, ("print('Hello, world!')", "<string>", "exec"),)
        class OpenFile(object):
            def __reduce__(self):
                return (builtins.exec, ("f = open('/etc/passwd', 'r'); print(f.read()); f.close()",))
        class Os(object):
            def __reduce__(self):
                import os
                return (os.system, ("echo 'Hello, world!'",))
        class MalSocket(object):
            def __reduce__(self):
                return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)

        if os.path.exists('malicious_socket.pkl'):
            os.remove('malicious_socket.pkl')
        with open('malicious_socket.pkl', 'wb') as f:
            pickle.dump(MalSocket(), f)

        my_list = ['a', 'b', 'c']
        with open('malicious_exec.pkl', 'wb') as f:
            pickle.dump((ExecuteCode(), my_list), f)

        student_names = ['Alice','Bob','Elena','Jane','Kyle']
        with open('student_file.pkl', 'wb') as f:  # open a text file
            pickle.dump(student_names, f) # serialize the list

        with open('malicious_eval.pkl', 'wb') as f:
            pickle.dump(EvalCode(), f)

        with open('malicious_compile.pkl', 'wb') as f:
            pickle.dump(CompileCode(), f)

        with open('malicious_open.pkl', 'wb') as f:
            pickle.dump(OpenFile(), f)

        # create a list to pickle
        fruits = ['apple', 'banana', 'orange']
        # open a file in write binary mode to pickle
        with open('fruits.pkl', 'wb') as f:
            # pickle the list
            pickle.dump(fruits, f)

        # create a dictionary to pickle
        person = {'name': 'John', 'age': 30, 'city': 'New York'}
        # open a file in write binary mode to pickle
        with open('person_dictionary.pkl', 'wb') as f:
            # pickle the dictionary
            pickle.dump(person, f)
        with open('safe_os.pkl', 'wb') as f:
            pickle.dump(Os(), f)


    def test_mal_exec(self):
        print("--------------------------mal_exec----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'malicious_exec.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
    def test_mal_compile(self):
        print("-----------------------mal_compile-------------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'malicious_compile.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
                # print(cdr.check_safety())
    def test_mal_open(self):
        print("-------------------------mal_open-----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'malicious_open.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

    def test_mal_eval(self):
        print("--------------------------malicious_eval----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'malicious_eval.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

    def test_malicious_socket(self):
        print("--------------------------malicious_socket----------------------------------")
        with patch('sys.stdout') as stdout:
            filename= 'malicious_socket.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
    def test_safe_student_file(self):
        print("--------------------------safe-student_file----------------------------------")
        with patch('sys.stdout') as stdout:
            filename='student_file.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
    def test_safe_fruits(self):
            print("--------------------------safe-fruits----------------------------------")
            with patch('sys.stdout') as stdout:
                filename='fruits.pkl'
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                # First run analysis.py
                analysis_result = analysis.check_safety(pickled_obj)
                self.assertFalse(False) # Expecting not clean
            if analysis_result == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
                MaliciousExtraction.scann(filename)
                print("Now removing the malicious data....")
                with patch('sys.stdout') as stdout:
                    cdr_result = cdr.check_safety(pickled_obj,filename)
                    self.assertTrue(True) # Expecting clean

                    # Finally, run analysis.py again
                    with open(filename, 'rb') as f:
                        pickled_data = f.read()
                    pickled_obj = Pickled.load(pickled_data)
                    analysis_result_2 = analysis.check_safety(pickled_obj)
                    self.assertTrue(True) # Expecting clean
                # Check stdout for expected messages
                if analysis_result_2 == True:
                    print("clean")
                    with open(filename, 'rb') as f:
                        pickled_data = pickle.load(f)
                    print(pickled_data)
                else:
                    print("not clean")
    def test_safe_person_dictionary(self):
        print("--------------------------safe-person_dictionary----------------------------------")
        with patch('sys.stdout') as stdout:
            filename='person_dictionary.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")
    def test_safe_os(self):
        print("--------------------------safe_os----------------------------------")
        with patch('sys.stdout') as stdout:
            filename='safe_os.pkl'
            with open(filename, 'rb') as f:
                pickled_data = f.read()
            pickled_obj = Pickled.load(pickled_data)
            # First run analysis.py
            analysis_result = analysis.check_safety(pickled_obj)
            self.assertFalse(False) # Expecting not clean
        if analysis_result == True:
            print("clean")
            with open(filename, 'rb') as f:
                pickled_data = pickle.load(f)
            print(pickled_data)
        else:
            print("not clean")
            MaliciousExtraction.scann(filename)
            print("Now removing the malicious data....")
            with patch('sys.stdout') as stdout:
                cdr_result = cdr.check_safety(pickled_obj,filename)
                self.assertTrue(True) # Expecting clean

                # Finally, run analysis.py again
                with open(filename, 'rb') as f:
                    pickled_data = f.read()
                pickled_obj = Pickled.load(pickled_data)
                analysis_result_2 = analysis.check_safety(pickled_obj)
                self.assertTrue(True) # Expecting clean
            # Check stdout for expected messages
            if analysis_result_2 == True:
                print("clean")
                with open(filename, 'rb') as f:
                    pickled_data = pickle.load(f)
                print(pickled_data)
            else:
                print("not clean")

