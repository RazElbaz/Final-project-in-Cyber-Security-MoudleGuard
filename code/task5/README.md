# Task 5
1. Produce one file that accepts the type of attack and produces a suitable attacked pickle with. cmd. -> **attack_cmd.py**  
To run:
python attack_cmd.py [attack_type]  
python attack_cmd.py -h -> to get help with attack_type arguments  

---

2. Produce one file that accepts the type of attack and produces a suitable attacked pickle with. cmd. and then removes with cdr the malicious part in the pickle file -> **cdr_cmd.py**  
To run:
python cdr_cmd.py [attack_type]

---
Please note that running or distributing ransomware is illegal and unethical. The information provided here is solely for educational purposes. I strongly advise against engaging in any malicious activities and encourage you to use your skills for positive and legal purposes.
Attention ♥ Open the files in a virtual machine to avoid any damage that may occur on the computer



To modify and compile the ransomware code in Linux, follow these steps:

1. Open a terminal and navigate to the directory where you have saved the ransomware source code files.

2. Use a text editor or the terminal-based text editor `nano` to open the ransomware code files. For example:

   ```
   nano Program.cs
   ```

3. Inside the text editor, you'll need to make modifications to the code to remove Windows-specific dependencies and replace them with Linux equivalents. This may involve replacing Windows Forms with alternative UI frameworks compatible with Linux, adapting file system operations, etc. The specific changes will depend on the code and your familiarity with C# and Linux development.

4. Save the modifications and exit the text editor.

5. Open the terminal and navigate to the directory containing the modified ransomware source code files.

6. Use the .NET Core CLI (Command-Line Interface) to compile the C# code. In the terminal, run the following command:

   ```
   dotnet build
   ```

   This command will compile the ransomware code and generate the necessary binaries.

7. If the build process completes successfully without any errors, you can now run the ransomware by executing the compiled binary. The command to run the program might look like this:

   ```
   dotnet run
   ```

   Keep in mind that the exact command might vary depending on the structure of the project and the specific requirements of the ransomware code.

Please note that modifying and running ransomware or engaging in any illegal activities is strictly prohibited. The instructions provided here are for educational purposes only. It is important to use your skills responsibly and ethically.
