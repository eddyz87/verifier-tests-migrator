import tree_sitter

class MatchError(Exception):
    def __init__(self, reason=None):
        super().__init__(reason)

def mnext(iterator):
    try:
        return next(iterator)
    except StopIteration:
        raise MatchError('Unexpected iterator end')

def match_any(*matchers):
    for m in matchers:
        assert callable(m)
        try:
            return m()
        except MatchError:
            pass
    raise MatchError('match_any failed')

class NodeWrapper:
    def __init__(self, node):
        self._node = node

    def _wrap(node):
        if isinstance(node, tree_sitter.Node):
            return NodeWrapper(node)
        return node

    def __getitem__(self, key):
        if isinstance(key, int):
            children = self._node.named_children
            child = children[key] if key <= len(children) else None
        else:
            child = self._node.child_by_field_name(key)
        if child is None:
            raise MatchError(f"can't find child '{key} in {self._node}'")
        return NodeWrapper._wrap(child)

    def __getattr__(self, attr):
        if attr == 'text':
            return self._node.text.decode('utf8')
        value = getattr(self._node, attr)
        if attr == 'named_children' or attr == 'children':
            return list(map(NodeWrapper._wrap, value))
        return value

    def mtype(self, type_name):
        if self._node.type != type_name:
            raise MatchError(f'Expecting type {type_name} for {self._node}')
        return self

    def mtext(self, text):
        if self.text != text:
            raise MatchError(f"Expecting '{text}' at {self._node}")
        return self

    def __str__(self):
        return f'!{str(self._node)}'

    def __repr__(self):
        return f'!{repr(self._node)}'
