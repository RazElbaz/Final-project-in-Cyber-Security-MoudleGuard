# Task 1
Learn about a pickle file: what it is, how to attack it. Execute an attack - I implemented a malicious pickle creation, I implemented sender and receiver programs to implement an attack that activates a code that runs automatically on the receiver and performs an attack.

The sender.py and receiverpy programs send a pickle file from the sender to the receiver, the receiver loads the information received from the sender and receives a list of passwords.

In the program Pickle_Arbitrary_Code_Execution.py there is a display of information output (can also be applied in sending with socket) such as passwords from the computer, groups, hosts and PAM.

In the program maliciousPickle.py there is a creation of a normal pickle file into which data was pushed and if we execute the following commands: cat payload.pkl, hexyl payload.pkl we can see the data that was pushed


**The best programs: receiver-all.py && sender-all.py**
