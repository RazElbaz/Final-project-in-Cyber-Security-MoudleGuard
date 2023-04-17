import pickle

student_names = ['Alice','Bob','Elena','Jane','Kyle']
with open('student_file.pkl', 'wb') as f:  # open a text file
    pickle.dump(student_names, f) # serialize the list
