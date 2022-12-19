from tree_sitter import Language

def build_grammar():
    Language.build_library('build/my-languages.so', ['tree-sitter-c'])
