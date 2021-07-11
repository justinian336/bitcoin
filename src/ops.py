"""
Implementing some Script operations.
Script is a non Turing-complete language for programming Bitcoin smart contracts.
Smart contracts are basically a sequence operations and elements (data), and a stack.
Some information on the available Ops can be found in:
https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
For simplification, the ops implemented here attempt an operation on the stack, and
return True in case of success or False otherwise.
There's quite a lot of opcodes to implement, so I'll just go for some common ones
"""

from encryption import hash256, hash160


# Duplicate the last element in the stack
def op_dup(stack):
    if len(stack) < 1:
        return False
    else:
        stack.append(stack[-1])
        return True


# Apply hash256 to the last element in the stack
def op_hash256(stack):
    if len(stack) < 1:
        return False
    else:
        element = stack.pop()
        stack.append(hash256(element))
        return True


def op_hash160(stack):
    # Could refactor this check into a decorator
    if len(stack) < 1:
        return False
    else:
        element = stack.pop()
        stack.append(hash160(element))
        return True


OPCODE_FUNCTIONS = {
    118: op_dup,
    169: op_hash160,
    170: op_hash256
}