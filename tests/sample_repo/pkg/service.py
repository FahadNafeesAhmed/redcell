"""Sample module. Known:
  symbols: Calculator, compute, main   (3)
  imports: add, mul from pkg.math_utils (2)
  calls:   compute -> mul, add (2); main -> Calculator, compute, print (3)
"""

from pkg.math_utils import add, mul


class Calculator:
    def compute(self, x):
        return mul(x, add(x, 1))


def main():
    c = Calculator()
    print(c.compute(3))
