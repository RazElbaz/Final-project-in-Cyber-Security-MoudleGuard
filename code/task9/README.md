# Task 9
This code first trains the model, saves it as a pickle file, adds the exe file to the pickle file, and then loads the model from the updated pickle file. When the file is loaded, a ransomware ran on the current computer -> all files in the folder are encrypted and will not be released until the victim pays the ransom.
Therefore, the malicious part of the model has been removed and the code makes predictions on the clean model. 

The code snippet trains a machine learning model using the MNIST dataset and performs predictions. 
1. Imports necessary libraries and modules.  
2. Defines a class `cdr` with methods for analyzing and checking the safety of pickled code objects.  
3. Defines a function `process_file` that processes a file by analyzing its safety and removing malicious data if found.  
4. Defines a class `scan_pickle_file` with a method `scann` that scans a pickle file for malicious content.  
5. Loads the MNIST dataset from a compressed pickle file (`mnist.pkl.gz`) and assigns the training and validation data to variables (`train_x`, `train_y`, `valid_x`, and `valid_y`).  
6. Sets up hyperparameters for a machine learning model, such as batch size (`bs`), learning rate (`lr`), and number of epochs (`epochs`). It also checks if a CUDA-compatible GPU is available and assigns the device `cuda` or `cpu` accordingly.  
7. Defines a function `preprocess` that reshapes the input data `x` into a 4-dimensional tensor and moves it to the specified device. It also defines a function called `get_dataloader` that creates and returns data loaders for training and evaluation data.  
8. Creates data loaders (`train_dl` and `valid_dl`) for the training and validation datasets using the `get_dataloader` function.  
9. Defines a convolutional neural network (CNN) model for image classification using PyTorch's `nn.Sequential` module. The model consists of convolutional layers, activation functions, pooling, and a flatten layer. It is moved to the specified device.  
10. Initializes an SGD optimizer for the model's parameters using stochastic gradient descent (SGD) optimization algorithm with the specified learning rate and momentum.  
11. Uses the `fit` function to train the model for the specified number of epochs using the training and validation data loaders. It computes the loss using the specified loss function (`F.cross_entropy`) and updates the model's parameters using the optimizer.  
12. Saves the trained model as a pickle file using the `pickle.dump` function.  
13. Appends an executable file (`S4VEtheD4TE.exe`) to the pickle file by creating an instance of the `OpenFile` class and using `pickle.dump`. This part is attempt to demonstrate a malicious scenario.  
14. Loads the model from the updated pickle file using `pickle.load`.  
15. Performs predictions on two input samples using the loaded model. It converts the input samples into tensors, passes them through the model, and retrieves the predicted classes.  
16. Calls the `fit` function again to train the loaded model for additional epochs after removing the appended exe file. It uses the same training and validation data loaders.  
 
The code involves tasks such as loading data, training a machine learning model, saving and loading models using pickle, and analyzing and removing malicious content from pickle files.
##  A detailed explanation of the main uses of the code:

1. cdr function:
The `cdr` function refers to the class that provides methods for analyzing and checking the safety of pickled code objects. A pickled code object is a serialized representation of Python objects that can be stored or transmitted. The `cdr` class contains methods to analyze the content of pickled code objects for any potential security risks or vulnerabilities.

2. MNIST dataset:
The MNIST dataset is a widely used benchmark dataset in the field of machine learning. It consists of a large collection of handwritten digits from 0 to 9, along with their corresponding labels. The dataset is often used for training and evaluating machine learning models, particularly for image classification tasks.

3. CNN model:
A CNN (Convolutional Neural Network) model is a type of neural network architecture commonly used for image classification tasks. In the code, a CNN model is defined using PyTorch's `nn.Sequential` module. This model consists of multiple layers, including convolutional layers, activation functions, pooling layers, and a flatten layer. It is designed to learn and extract features from images to classify them into different classes (in this case, the digits 0 to 9).

4. SGD optimizer:
The SGD (Stochastic Gradient Descent) optimizer is an optimization algorithm commonly used for training machine learning models. In the code, an SGD optimizer is initialized with specific parameters such as learning rate and momentum. The optimizer is responsible for updating the parameters of the model during training, using gradient descent to minimize the loss and improve the model's performance.

5. fit function:
The `fit` function is likely a custom function defined in the code. It is used to train the machine learning model on the MNIST dataset. The function takes the model, optimizer, loss function, and data loaders as inputs. During training, it iterates over the dataset for the specified number of epochs, calculates the loss using the specified loss function, and updates the model's parameters using the optimizer to improve its performance.

6. Executable file (`S4VEtheD4TE.exe`):
The code snippet includes an unexpected part where an executable file named `S4VEtheD4TE.exe` is appended to the pickle file.This part is an attempt to demonstrate a malicious scenario. It is important to note that appending executable files, especially with unfamiliar sources, can be potentially harmful and is not recommended unless you have a legitimate and trusted source for the file.

Overall, the code performs various tasks such as analyzing pickled code objects, loading and processing the MNIST dataset, training a CNN model, optimizing the model's parameters using SGD, and manipulating pickle files. However, it also includes suspicious elements like appending an executable file, which should be approached with caution.
