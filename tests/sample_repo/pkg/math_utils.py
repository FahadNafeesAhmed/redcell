"""Sample module. Known: 2 symbols (add, mul), 1 call (mul -> add)."""


def add(a, b):
    return a + b


def mul(a, b):
    return add(a, a) * b
