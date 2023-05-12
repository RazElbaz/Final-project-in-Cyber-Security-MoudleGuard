# Undergraduate-final-project-in-Cyber-Security
## Pickle file
The pickle module in Python provides functions for serializing and deserializing Python objects into a binary format. The module defines two main classes: Pickler and Unpickler, which are used to serialize and deserialize Python objects, respectively.

The Pickler class is used to convert a Python object into a byte stream, while the Unpickler class is used to convert a byte stream back into a Python object.

The pickle module also defines several functions for serializing and deserializing objects, including:

- pickle.dump(obj, file, protocol=None, *, fix_imports=True)
  - This function serializes the object 'obj' and writes it to the open file object 'file'. The 'protocol' argument is an optional integer that specifies the pickle protocol to use.

- pickle.dumps(obj, protocol=None, *, fix_imports=True)
  - This function serializes the object 'obj' and returns a bytes object containing the serialized data. The 'protocol' argument is an optional integer that specifies the pickle protocol to use.

- pickle.load(file, *, fix_imports=True, encoding="ASCII", errors="strict")
  - This function reads a pickled object from the open file object 'file' and returns the deserialized Python object.

- pickle.loads(bytes_object, *, fix_imports=True, encoding="ASCII", errors="strict")
  - This function deserializes a pickled object from the bytes object 'bytes_object' and returns the deserialized Python object.

The pickle module uses a binary format to serialize Python objects, which consists of a series of bytes that represent the object in a compact and efficient way. The format includes a protocol version number, a serialized representation of the object's data, and a series of instructions that describe how to recreate the object. The format is designed to be flexible and extensible, and can handle a wide range of Python objects.
