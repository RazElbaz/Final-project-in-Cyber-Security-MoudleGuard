# # from fickling.pickle import Pickled
# # from fickling.analysis import check_safety
# # import pickle
# #
# # # Load the pickled object from a file
# # with open('unsafe.pkl', 'rb') as f:
# #     pickled_data = f.read()
# #
# # # Deserialize the pickled data into a Pickled object
# # pickled_obj = Pickled.load(pickled_data)
# #
# # # Check the safety of the pickled data
# # if not check_safety(pickled_obj):
# #     print('WARNING: The pickled data may contain unsafe or malicious code!')
# # else:
# #     print('The pickled data is safe to use.')
# # import pickletools
# #
# # with open('unsafe.pkl', 'rb') as f:
# #     data = f.read()
# #
# # for op, *args in pickletools.genops(data):
# #     if op.name in ['GLOBAL', 'REDUCE', 'BUILD']:
# #         print(f"WARNING: {op.name} operation found with args {args}. This may be unsafe.")
# #     else:
# #         print(f"Safe operation: {op.name} with args {args}.")
# #
# # import pickletools
# #
# # with open('unsafe.pkl', 'rb') as f:
# #     data = f.read()
# #
# # pickletools.dis(data)
# #
# import pickletools
# from fickling.pickle import Pickled
# from fickling.analysis import check_safety
# import pickle
#
# # Load the pickled object from a file
# with open('unsafe.pkl', 'rb') as f:
#     pickled_data = f.read()
#
# # Deserialize the pickled data into a Pickled object
# pickled_obj = Pickled.load(pickled_data)
#
# # Check the safety of the pickled data
# if not check_safety(pickled_obj):
#     print('WARNING: The pickled data may contain unsafe or malicious code!')
# else:
#     print('The pickled data is safe to use.')
# with open('unsafe2.pkl', 'rb') as f:
#     data = f.read()
#
# # Use pickletools to inspect the contents of the pickle file
# # This will raise an exception if the file contains malicious code
# try:
#     for op, *args in pickletools.genops(pickletools.optimize(data)):
#         # Inspect each operation to make sure it is safe to execute
#         # ...
#         pass
# except Exception as e:
#     print(f'Error inspecting pickle data: {e}')
#
# # Use pickletools to disassemble the pickle file and inspect the resulting bytecode
# try:
#     pickletools.dis(pickletools.optimize(data))
# except Exception as e:
#     print(f'Error disassembling pickle data: {e}')
import pickle
import pickletools
import io

# Open pickle file for reading in binary mode
# with open('student_file.pkl', 'rb') as f:
#     # Create a BytesIO object to hold the file's contents
#     data = f.read()

# for op in pickletools.genops(data):
#     # print(op)
#     if type(op[1]) == str:
#         # print(op[1])

with open('unsafe.pkl', 'rb') as f:
    # Create a BytesIO object to hold the file's contents
    data = pickle.load(f)

print(data)
