#!/usr/bin/python3

from tree_sitter import Language

def build_grammar():
    Language.build_library('build/my-languages.so', ['tree-sitter-c'])

if __name__ == '__main__':
    build_grammar()
