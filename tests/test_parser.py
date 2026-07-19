from redcell.ingest.parser import parse_python

SERVICE = (
    "from pkg.math_utils import add, mul\n"
    "\n"
    "class Calculator:\n"
    "    def compute(self, x):\n"
    "        return mul(x, add(x, 1))\n"
    "\n"
    "def main():\n"
    "    c = Calculator()\n"
    "    print(c.compute(3))\n"
)


def test_symbols():
    pf = parse_python("service.py", SERVICE)
    by_name = {s.name: s for s in pf.symbols}
    assert set(by_name) == {"Calculator", "compute", "main"}
    assert by_name["Calculator"].kind == "class"
    assert by_name["compute"].kind == "method"
    assert by_name["compute"].qualname == "Calculator.compute"
    assert by_name["main"].kind == "function"


def test_imports():
    pf = parse_python("service.py", SERVICE)
    imported = {(i.module, i.name) for i in pf.imports}
    assert imported == {("pkg.math_utils", "add"), ("pkg.math_utils", "mul")}


def test_calls_attributed_to_enclosing_function():
    pf = parse_python("service.py", SERVICE)
    edges = {(c.caller, c.callee) for c in pf.calls}
    # compute calls mul and add
    assert ("Calculator.compute", "mul") in edges
    assert ("Calculator.compute", "add") in edges
    # main calls Calculator, compute, print
    assert ("main", "Calculator") in edges
    assert ("main", "compute") in edges
    assert ("main", "print") in edges
    assert len(pf.calls) == 5


def test_module_level_calls_attributed_to_module():
    pf = parse_python("m.py", "print('hi')\n")
    assert pf.calls[0].caller == "<module>"
    assert pf.calls[0].callee == "print"


def test_syntax_error_propagates():
    import pytest

    with pytest.raises(SyntaxError):
        parse_python("bad.py", "def (:\n")
