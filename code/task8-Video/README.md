# Task 8
There is an unreal ransomware scam written on dotnet  
https://github.com/araujo88/S4VEtheD4TE  
The goal is to create an exe and link it to the attack  
To activate:
1. for the file: install .net core version 3.1 (exactly) and visual studio -2019
2. create a folder "encryption_tests" ion drive c:\
add file you do not need - they will be encrypted

The idea is to run the attack that will execute the exe file and once it will execute you will see a ransom note.

In the folder attack_exe_file there is the compiled library-> you can download directly but be careful it contains malicious ♥ Download the folder to the VM


`PickleCDR.ipynb`: Creating a model that contains an exe file that triggers a ransomware attack.
Loading the model without a protected path and without the cdr.py written library led to an attack.
The pickle file is then loaded in protected form -> using the directory ficking.pickle import Pickled
It can be seen that the attack is not activated.
The program runs cdr.py removes the malware, and shows the "clean" data that was in the file.
Now you can load the pickle file in the protected way, and in the unprotected way -> in both ways the ransomware attack will not be activated.


`attack_exe_file.zip` :  The compiled library-> you can download directly but be careful it contains malicious 

`pickleCDR.mp4` : Video of running jupyter notebook
