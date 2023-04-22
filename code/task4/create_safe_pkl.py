import builtins
import pickle
import socket

class Os(object):
    def __reduce__(self):
        import os
        return (os.system, ("echo 'Hello, world!'",))



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

