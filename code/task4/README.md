# Task 4
The task is to modify the pickle package by removing parts that could be used for malicious attacks, add a new capability called cdr.py, and then test that this change works by running parse and cdr, and verifying that parse returns "clean" after cdr is called.
I need to remove the parts that can cause an attack because a pickle has parts that make it explosive. I want to take their package. Add a new capability called cdr.py. and then in the tests to perform:  
analysis  
cdr  
analysis  
when the latter should show me "clean"  

Here are the steps I will take:

1. I will identify the parts of the pickle package that may be dangerous and should be removed. I'll refer to the Python documentation on pickle for more information.

2. After identifying the parts that need to be removed, a create a different version of the pickle package that does not include these parts. I will modify the existing pickle package or create a new package that is a different version of the original.

3. I will add a new capability called cdr.py. I will create this file in the same directory as the modified pickle package.

4. In cdr.py, I will write code that performs the desired functionality.

5. I will write tests that call the analysis and cdr, I will make sure that the analysis returns "clean" after reading cdr.

6. I will run the tests and make sure they pass.

7. If the tests fail, I will debug the code and fix problems.
8. After the tests pass, I can use the custom pickle package and cdr.py in your project.

♥Changing a Python core package like a pickle can be dangerous and may have unintended consequences. It's important to thoroughly test your changes and make sure they don't break any existing code.


### What remains to be done:
Check with unsafe again  
Add the test with fkicking  
Add more tests in general  
Create more pickle files and test  
