import pickle
import json

class MySafeClass:
    def __init__(self, name):
        self.name = name

class MyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow MySafeClass to be unpickled
        if name == 'MySafeClass':
            print(name)
            return MySafeClass
        else:
            print(name)
            raise pickle.UnpicklingError("Invalid class: {}".format(name))

# Load the pickle file
with open('safe.pkl', 'rb') as f:
    # Create a MyUnpickler to safely unpickle the data
    unpickler = MyUnpickler(f)
    print(unpickler)

    # Unpickle the data
    data = unpickler.load()

# Serialize the data to JSON
json_data = json.dumps({'data': data})

# Write the serialized data to a file
with open('data.json', 'w') as f:
    f.write(json_data)
