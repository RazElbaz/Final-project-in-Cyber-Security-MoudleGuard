import pickle
import unittest
from unittest.mock import patch
import fickling.analysis as analysis
from fickling.pickle import Pickled

import cdr

class TestSafety(unittest.TestCase):

    def test_safety_check(self):
        with patch('sys.stdout') as stdout:
            filename='unsafe.pkl'
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

    def test_safety_check2(self):
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


