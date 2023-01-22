import io
import ast
import inspect
from dataclasses import dataclass

@dataclass
class Var:
    name: str

class DString:
    def __init__(self, string, vars):
        tree = ast.parse(f"f'{string}'", mode='eval')
        self.vars = {}
        self.template = []
        self.dst_action = None
        self.st_mem = False
        match tree:
            case ast.Expression(body=ast.JoinedStr(values=values)):
                for val in values:
                    match val:
                        case ast.Constant(value=v):
                            self.template.append(v)
                        case ast.FormattedValue(value=ast.Name(id=name)):
                            self.template.append(Var(name))
                            self.vars[name] = vars[name]
                        case _:
                            raise Exception(f'Unexpected val {val}')
            case _:
                raise Exception(f'Unexpected tree {tree}')

    def __str__(self):
        with io.StringIO() as out:
            for val in self.template:
                match val:
                    case str(): out.write(val)
                    case Var(): out.write(str(self.vars[val.name]))
            return out.getvalue()

def d(string, dst_action=None):
    s = DString(string, inspect.currentframe().f_back.f_locals)
    s.dst_action = dst_action
    return s
