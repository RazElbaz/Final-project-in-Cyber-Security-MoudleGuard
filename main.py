import pickle
import fickling.analysis as analysis
import scan_pickle_file
import cdr
from fickling.pickle import Pickled

student_names = ['Alice','Bob','Elena','Jane','Kyle']
pickle_bin = pickle.dumps(student_names)
p = Pickled.load(pickle_bin)
p.insert_python_exec("with open('/etc/passwd','r') as r: print(r.readlines())")
p.insert_python_exec("with open('/etc/group','r') as r: print(r.readlines())")
p.insert_python_exec("import module print('malicious')")
p.insert_python_exec("import os  os.system('echo Malicious code!')")

with open('unsafe.pkl', 'wb') as f:
            p.dump(f)
filename = 'unsafe.pkl'

try:
    with open(filename, 'rb') as f:
        pickled_data = f.read()


    analysis_result = analysis.check_safety(Pickled.load(pickled_data))
    if analysis_result:
        # The pickled object is safe
        # Do something with the pickled object
        print("clean")
        with open(filename, 'rb') as f:
            pickled_data = pickle.load(f)
        print(pickled_data)
    else:
        # The pickled object is flagged as malicious or unsafe
        raise ValueError("The pickled object is flagged as malicious or unsafe.")


except (pickle.UnpicklingError, ValueError,AttributeError) as e:
    # Handle the case when the pickled object is flagged as malicious or unsafe
    print("not clean")
    scan_pickle_file.scann(filename)
    print("Now removing the malicious data....")
    cdr_result = cdr.check_safety(Pickled.load(pickled_data), filename)
    # print(cdr_result)

    with open(filename, 'rb') as f:
             pickled_data = f.read()
    pickled_obj = Pickled.load(pickled_data)
    analysis_result_2 = analysis.check_safety(pickled_obj)
    print(analysis_result_2)
    if analysis_result_2:
        print("clean")
        print("\nThe clean data left in the file:")
        with open(filename, 'rb') as f:
            pickled_data = pickle.load(f)
        print(pickled_data)
    else:
        print("not clean")

