import ast
import sys
from typing import Optional, TextIO, Tuple
import pickle

import fickling.analysis

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from fickling.pickle import Interpreter, Pickled

def code(self) -> str:
    """
    Returns the string representation of the code object that was pickled.
    """
    code = self.pickled['code']
    return code.co_code.decode('utf-8')
def check_safety(
    pickled: Pickled,filename, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None
) -> bool:
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr

    properties = pickled.properties
    likely_safe = True
    reported_shortened_code = set()

    def shorten_code(ast_node) -> Tuple[str, bool]:
        code = unparse(ast_node).strip()
        if len(code) > 32:
            cutoff = code.find("(")
            if code[cutoff] == "(":
                shortened_code = f"{code[:code.find('(')].strip()}(...)"
            else:
                shortened_code = code
        else:
            shortened_code = code
        was_already_reported = shortened_code in reported_shortened_code
        reported_shortened_code.add(shortened_code)
        return shortened_code, was_already_reported

    safe_lines = []
    with open(filename, 'rb') as f:
        code=str(f.read())
    for line in code.split('\n'):
        print(line)
        try:
            ast_node = compile(line, '<string>', 'exec', ast.PyCF_ONLY_AST)

        except SyntaxError:
            # If the line doesn't parse, assume it's unsafe and include it in the new file
            safe_lines.append(line)
            continue
        is_safe = True
        for node in ast.walk(ast_node):
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == 'eval'
                ):
                    # eval is always unsafe
                    is_safe = False
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'loads'
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'pickle'
                ):
                    # loading pickles is unsafe, unless it's being done by the check_safety function
                    is_safe = False
            elif isinstance(node, ast.Import):
                # importing modules is unsafe, unless it's a standard library module
                for alias in node.names:
                    if not alias.name.startswith('_') and alias.name not in sys.modules:
                        is_safe = False
            elif isinstance(node, ast.ImportFrom):
                # importing from modules is unsafe, unless it's a standard library module
                if not node.module.startswith('_') and node.module not in sys.modules:
                    is_safe = False
            elif ("eval" or "exec" or "compile" or "open") in line:
                is_safe = False
            elif ("__builtin__" or "os" or "subprocess" or "sys" or "builtins" or "socket") in line:
                is_safe = False
        if is_safe:
            safe_lines.append(line)

    # write the safe lines to a new pickle file
    with open('safe.pkl', 'wb') as f:
        pickle.dump('\n'.join(safe_lines), f)
        print(safe_lines)

    if not safe_lines:
        # If there are no safe lines, return False to indicate that the pickle is unsafe
        return False

    if likely_safe:
        stderr.write(
            "Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may "
            "still be unsafe.\n\nDo not unpickle this file if it is from an untrusted source!\n"
        )
        return True
    else:
        return False

filename='unsafe.pkl'
with open(filename, 'rb') as f:
    pickled_data = f.read()
pickled_obj = Pickled.load(pickled_data)
print(fickling.analysis.check_safety(pickled_obj))
check_safety(pickled_obj,filename)
with open('safe.pkl', 'rb') as f:

    pickled_data = f.read()
    print(pickled_data.decode('utf-8'))
    print(str(pickled_data))
pickled_obj = Pickled.load(pickled_data)
print(fickling.analysis.check_safety(pickled_obj))


