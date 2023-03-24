#!/usr/bin/python3

import os
import io
import re
import sys
import cfg
import logging
import argparse
import tree_sitter
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
from tree_sitter import Language, Parser

from dstring import *
from tree_sitter_matching import *

C_LANGUAGE = Language('build/my-languages.so', 'c')

def is_debug():
    return logging.root.getEffectiveLevel() <= logging.DEBUG

def pptree(tree):
    with io.StringIO() as out:
        def recur(node, lvl):
            for _ in range(0, lvl):
                out.write('  ')
            out.write(node.type)
            if node.child_count > 0:
                out.write(":\n")
            elif node.is_named:
                out.write(f": {node.text}\n")
            else:
                out.write("\n")
            for child in node.children:
                if not child.is_named and node.type != 'binary_expression':
                    continue
                recur(child, lvl + 1)
        recur(tree, 0)
        return out.getvalue()

def parse_c_string(text):
    parser = Parser()
    parser.set_language(C_LANGUAGE)
    tree = parser.parse(bytes(text, encoding='utf8'))
    return tree.root_node

#################################
##### Instructions matching #####
#################################

def text_to_int(text):
    if text.startswith('0x') or text.startswith('-0x'):
        return int(text, 16)
    else:
        return int(text)

@dataclass(frozen=True)
class Imm:
    text: str
    base_name: str = None
    insn: bool = False

class CallMatcher:
    imm_counter = 0

    def __init__(self, node, pending_fixup):
        node.mtype('call_expression')
        self._args = iter(node['arguments'].named_children)
        self._pending_fixup = pending_fixup

    def _next_arg(self):
        try:
            return next(self._args)
        except StopIteration:
            raise MatchError()

    def _ident(self, expected=None):
        it = self._next_arg().mtype('identifier')
        if expected:
            it.mtext(expected)
        return it.text

    def ensure_args_consumed(self):
        try:
            next(self._args)
            raise MatchError()
        except StopIteration:
            pass

    def _regno(self):
        arg = self._next_arg()

        def _regno_ident():
            ident = arg.mtype('identifier').text
            if m := re.match(r'^BPF_REG_([0-9]+)$', ident):
                return m[1]
            match ident:
                case 'BPF_REG_ARG1': return 1
                case 'BPF_REG_ARG2': return 2
                case 'BPF_REG_ARG3': return 3
                case 'BPF_REG_ARG4': return 4
                case 'BPF_REG_ARG5': return 5
                case 'BPF_REG_CTX' : return 6
                case 'BPF_REG_FP'  : return 10
            raise MatchError()

        def _regno_number():
            num = int(arg.mtype('number_literal').text)
            if num < 0 or num > 10:
                raise MatchError(f'Register number out of range {num}')
            return num

        return match_any(_regno_ident, _regno_number)

    def reg(self):
        return f'r{self._regno()}'

    def reg32(self):
        return f'w{self._regno()}'

    def size(self):
        arg = self._next_arg()

        def _size_ident():
            match arg.mtype('identifier').text:
                case 'BPF_DW': return 'u64'
                case 'BPF_W' : return 'u32'
                case 'BPF_H' : return 'u16'
                case 'BPF_B' : return 'u8'
                case _: raise MatchError()

        def _size_number():
            match text_to_int(arg.mtype('number_literal').text):
                case 0x18: return 'u64'
                case 0x00: return 'u32'
                case 0x08: return 'u16'
                case 0x10: return 'u8'
                case _: raise MatchError()

        return match_any(_size_ident, _size_number)

    def _intern_expr(self, node):
        if node.type == 'number_literal':
            return node.text
        return Imm(node.text)

    def expr(self):
        return self._intern_expr(self._next_arg())

    def off(self):
        arg = self._next_arg()
        match arg.type:
            case 'number_literal':
                text = arg.text
                if re.match(r'^[+-]', text):
                    return text[0], text[1:]
                else:
                    return '+', text
            case 'unary_expression' if arg['operator'].text in ['-', '+']:
                return arg['operator'].text, Imm(arg['argument'].text)
            # SHRT_MIN is special, it is defined as -32768,
            # numbers are substituted literally into the asm template,
            # thus leading to the following sequence:
            # asm ("r0 = *(u8*)(r1 + %[shrt_min]);", [shrt_min]"i"(SHRT_MIN))
            # ->
            # asm ("r0 = *(u8*)(r1 + -32768);")
            # which can't be parsed.
            case 'identifier' if arg.text == 'SHRT_MIN':
                return '', Imm(arg.text)
            case _:
                return '+', Imm(arg.text)

    def number(self):
        return text_to_int(self._next_arg().mtype('number_literal').text)

    def bpf_func_ident(self):
        raw_func = self._ident()
        func_match = re.match(r'BPF_FUNC_(.+)', raw_func)
        if not func_match:
            raise MatchError(d('Strange func name {raw_func}'))
        return Imm(f'bpf_{func_match[1]}')

    _ATOMIC_OPS = {
        'BPF_ADD': '+=',
        'BPF_AND': '&=',
        'BPF_OR' : '|=',
        'BPF_XOR': '^='
        }

    _ATOMIC_FETCH_OPS = {
        'BPF_ADD': 'add',
        'BPF_AND': 'and',
        'BPF_OR' : 'or',
        'BPF_XOR': 'xor'
        }

    _ALU_OPS = {
        'BPF_MOV': '=',
        'BPF_ADD': '+=',
        'BPF_SUB': '-=',
        'BPF_MUL': '*=',
        'BPF_DIV': '/=',
        'BPF_MOD': '%%=',
        'BPF_OR' : '|=',
        'BPF_AND': '&=',
        'BPF_LSH': '<<=',
        'BPF_RSH': '>>=',
        'BPF_XOR': '^=',
        'BPF_ARSH': 's>>=',
        }

    _JMP_OPS = {
        'BPF_JEQ' : '==',
        'BPF_JGT' : ">",
        'BPF_JGE' : ">=",
        'BPF_JNE' : "!=",
        'BPF_JSGT': "s>",
        'BPF_JSGE': "s>=",
        'BPF_JLT' : "<",
        'BPF_JLE' : "<=",
        'BPF_JSLT': "s<",
        'BPF_JSLE': "s<=",
        }

    def match_dict(node, d, name):
        text = node.text
        if text in d:
            return d[text]
        raise MatchError(f'Unexpected {name}: {text}')

    def atomic_op(self):
        def match_fetch(node):
            return CallMatcher.match_dict(
                node, CallMatcher._ATOMIC_FETCH_OPS, 'atomic fetch op')

        arg = self._next_arg()
        if arg.type == 'binary_expression' and arg['operator'].text == '|':
            if arg['left'].text == 'BPF_FETCH' and arg['right'].type == 'identifier':
                return match_fetch(arg['right']), True
            if arg['right'].text == 'BPF_FETCH' and arg['left'].type == 'identifier':
                return match_fetch(arg['left']), True
        elif arg.type == 'identifier':
            return CallMatcher.match_dict(arg, CallMatcher._ATOMIC_OPS, 'atomic op'), False

        raise MatchError(f'Strange atomic_op {arg}')

    def alu_op(self):
        op = self._ident()
        if op in CallMatcher._ALU_OPS:
            return CallMatcher._ALU_OPS[op]
        raise MatchError(f'Unsupported ALU op: {op}')

    def jmp_op(self):
        op = self._ident()
        if op in CallMatcher._JMP_OPS:
            return CallMatcher._JMP_OPS[op]
        raise MatchError(f'Unsupported JMP op: {op}')

    def zero(self):
        self._next_arg().mtext('0')

    def one(self):
        self._next_arg().mtext('1')

    def jmp_call(self):
        arg = self._next_arg()
        arg.mtype('binary_expression')
        arg['operator'].mtext('|')
        arg['left'].mtext('BPF_JMP')
        arg['right'].mtext('BPF_CALL')

class InsnMatchers:
    def BPF_MOV64_REG(m):
        dst = m.reg()
        src = m.reg()
        return d('{dst} = {src};', 'w')

    def BPF_ALU64_IMM(m):
        op = m.alu_op()
        dst = m.reg()
        imm = m.expr()
        dst_action = 'w' if op == '=' else 'rw'
        return d('{dst} {op} {imm};', dst_action)

    def BPF_ALU32_IMM(m):
        op = m.alu_op()
        dst = m.reg32()
        imm = m.expr()
        dst_action = 'w' if op == '=' else 'rw'
        return d('{dst} {op} {imm};', dst_action)

    def BPF_ALU64_REG(m):
        op = m.alu_op()
        dst = m.reg()
        src = m.reg()
        dst_action = 'w' if op == '=' else 'rw'
        return d('{dst} {op} {src};', dst_action)

    def BPF_ALU32_REG(m):
        op = m.alu_op()
        dst = m.reg32()
        src = m.reg32()
        dst_action = 'w' if op == '=' else 'rw'
        return d('{dst} {op} {src};', dst_action)

    def BPF_ALU32_IMM___BPF_NEG(m):
        m._next_arg().mtext('BPF_NEG')
        dst = m.reg32()
        imm = m.number()
        if imm != 0:
            raise MatchError(f'BPF_ALU_IMM(BPF_NEG, ...) expect imm to be zero: {imm}')
        return d('{dst} = -{dst};', 'rw')

    def BPF_ALU64_IMM___BPF_NEG(m):
        m._next_arg().mtext('BPF_NEG')
        dst = m.reg()
        imm = m.number()
        if imm != 0:
            raise MatchError(f'BPF_ALU_IMM(BPF_NEG, ...) expect imm to be zero: {imm}')
        return d('{dst} = -{dst};', 'rw')

    def BPF_ALU32_REG___BPF_NEG(m):
        m._next_arg().mtext('BPF_NEG')
        dst = m.reg32()
        src = m.reg32()
        return d('{dst} = -{src};', 'w')

    def BPF_ALU64_REG___BPF_NEG(m):
        m._next_arg().mtext('BPF_NEG')
        dst = m.reg()
        src = m.reg()
        return d('{dst} = -{src};', 'w')

    def BPF_MOV64_IMM(m):
        dst = m.reg()
        imm = m.expr()
        return d('{dst} = {imm};', 'w')

    def BPF_MOV32_IMM(m):
        dst = m.reg32()
        imm = m.expr()
        return d('{dst} = {imm};', 'w')

    def BPF_MOV32_REG(m):
        dst = m.reg32()
        src = m.reg32()
        return d('{dst} = {src};', 'w')

    def BPF_LD_IMM64(m):
        dst = m.reg()
        imm = m.expr()
        insn = d('{dst} = {imm} ll;', 'w')
        insn.double_size = True
        return insn

    def BPF_LDX_MEM(m):
        sz = m.size()
        dst = m.reg()
        src = m.reg()
        sign, off = m.off()
        return d('{dst} = *({sz}*)({src} {sign} {off});', 'w')

    def BPF_ST_MEM(m):
        sz = m.size()
        dst = m.reg()
        sign, off = m.off()
        imm = m.expr()
        insn = d('*({sz}*)({dst} {sign} {off}) = {imm};', 'r')
        insn.st_mem = True
        return insn

    def BPF_STX_MEM(m):
        sz = m.size()
        dst = m.reg()
        src = m.reg()
        sign, off = m.off()
        return d('*({sz}*)({dst} {sign} {off}) = {src};', 'r')

    def BPF_ATOMIC_OP(m):
        sz = m.size()
        op, fetch = m.atomic_op()
        dst = m.reg()
        match sz:
            case 'u64':
                src = m.reg()
            case 'u32':
                src = m.reg32()
            case _:
                raise MatchError(f'Unexpected size for atomic op: {sz}')
        sign, off = m.off()
        if fetch:
            return d('{src} = atomic_fetch_{op}(({sz} *)({dst} {sign} {off}), {src});')
        else:
            return d('lock *({sz} *)({dst} {sign} {off}) {op} {src};')

    def BPF_ATOMIC_OP___xchg(m):
        sz = m.size()
        m._ident('BPF_XCHG')
        match sz:
            case 'u64':
                op = 'xchg_64'
                dst = m.reg()
                src = m.reg()
            case 'u32':
                op = 'xchg32_32'
                dst = m.reg32()
                src = m.reg32()
            case _:
                raise MatchError(f'Unexpected size for atomic op: {sz}')
        sign, off = m.off()
        return d('{src} = {op}({dst} {sign} {off}, {src});')

    def BPF_ATOMIC_OP___cmpxchg(m):
        sz = m.size()
        m._ident('BPF_CMPXCHG')
        dst = m.reg()
        match sz:
            case 'u64':
                op  = 'cmpxchg_64'
                r0  = 'r0'
                src = m.reg()
            case 'u32':
                op  = 'cmpxchg32_32'
                r0  = 'w0'
                src = m.reg32()
            case _:
                raise MatchError(f'Unexpected size for atomic op: {sz}')
        sign, off = m.off()
        return d('{r0} = {op}({dst} {sign} {off}, {r0}, {src});')

    def BPF_LD_MAP_FD(m):
        if type(m._pending_fixup) == MapFixup:
            dst = m.reg()
            imm = m.expr()
            insn = d('{dst} = {imm} ll;')
            insn.double_size = True
            insn.dst_action = 'w'
            return insn
        else:
            dst = m._next_arg().text
            imm = m._next_arg().text
            raw = Imm(f'BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, {dst}, ' +
                      f'BPF_PSEUDO_MAP_FD, 0, {imm})',
                      base_name='ld_map_fd',
                      insn=True)
            return [d('.8byte {raw};'),
                    d('.8byte 0;')]

    def BPF_LD_ABS(m):
        sz = m.size()
        imm = m.expr()
        return d('r0 = *({sz}*)skb[{imm}];')

    def BPF_LD_IND(m):
        sz = m.size()
        src = m.reg()
        return d('r0 = *({sz}*)skb[{src}];')

    def BPF_JMP_IMM(m):
        op = m.jmp_op()
        dst = m.reg()
        imm = m.expr()
        goto = m.number()
        return d('if {dst} {op} {imm} goto {goto};', 'r')

    def BPF_JMP32_IMM(m):
        op = m.jmp_op()
        dst = m.reg32()
        imm = m.expr()
        goto = m.number()
        return d('if {dst} {op} {imm} goto {goto};', 'r')

    def BPF_JMP_REG(m):
        op = m.jmp_op()
        dst = m.reg()
        src = m.reg()
        goto = m.number()
        return d('if {dst} {op} {src} goto {goto};', 'r')

    def BPF_JMP32_REG(m):
        op = m.jmp_op()
        dst = m.reg32()
        src = m.reg32()
        goto = m.number()
        return d('if {dst} {op} {src} goto {goto};', 'r')

    def BPF_JMP_IMM___goto(m):
        m._next_arg().mtype('identifier').mtext('BPF_JA')
        m.zero()
        m.zero()
        goto = m.number()
        return d('goto {goto};')

    def BPF_JMP_A(m):
        goto = m.number()
        return d('goto {goto};')

    def BPF_EXIT_INSN(m):
        return d('exit;')

    def BPF_CALL_REL(m):
        goto = m.number()
        return d('call {goto};')

    def BPF_RAW_INSN___bpf_call(m):
        m.jmp_call()
        m.zero()
        m.one()
        m.zero()
        goto = m.number()
        return d('call {goto};')

    def BPF_RAW_INSN___helper_call(m):
        m.jmp_call()
        m.zero()
        m.zero()
        m.zero()
        func = m.bpf_func_ident()
        return d('call {func};')

    def BPF_RAW_INSN___kfunc_call(m):
        m.jmp_call()
        m.zero()
        m._next_arg().mtype('identifier').mtext('BPF_PSEUDO_KFUNC_CALL')
        m.zero()
        m.zero()
        if type(m._pending_fixup) != KFuncFixup:
            raise MatchError(f'Expecting pending kfunc fixup')
        imm = Imm(m._pending_fixup.kfunc)
        return d('call {imm};')

    def BPF_EMIT_CALL(m):
        func = m.bpf_func_ident()
        return d('call {func};')

def func_matchers_map():
    func_matchers = defaultdict(list)
    for name, fn in InsnMatchers.__dict__.items():
        if not callable(fn):
            continue
        func_name_match = re.match(r'^(BPF_.+?)(?:___.+)?$', name)
        if not func_name_match:
            continue
        func_name = func_name_match[1]
        func_matchers[func_name].append(fn)
    return defaultdict(tuple, func_matchers)

FUNC_MATCHERS = func_matchers_map()

EIGHT_BYTE_INSNS = set(
    ['BPF_ALU64_IMM', 'BPF_ALU32_IMM', 'BPF_ALU64_REG', 'BPF_ALU32_REG',
     'BPF_MOV64_IMM', 'BPF_MOV32_IMM', 'BPF_MOV64_REG', 'BPF_MOV32_REG',
     'BPF_JMP_IMM'  , 'BPF_JMP32_IMM', 'BPF_JMP_REG'  , 'BPF_JMP32_REG',
     'BPF_JMP_A'    , 'BPF_EXIT_INSN', 'BPF_EMIT_CALL', 'BPF_CALL_REL' ,
     'BPF_LDX_MEM'  , 'BPF_ST_MEM'   , 'BPF_STX_MEM'  , 'BPF_ATOMIC_OP',
     'BPF_LD_ABS'   , 'BPF_LD_IND'   , 'BPF_RAW_INSN'
    ])

@dataclass
class MapFixup:
    pass

@dataclass
class KFuncFixup:
    kfunc: str

def convert_insn(call_node, pending_fixup):
    errors = []
    node_func_name = call_node['function'].text
    for fn in FUNC_MATCHERS[node_func_name]:
        m = CallMatcher(call_node, pending_fixup)
        try:
            result = fn(m)
            m.ensure_args_consumed()
            return result
        except MatchError as e:
            if is_debug():
                errors.append((fn, e))

    if node_func_name in EIGHT_BYTE_INSNS:
        imm_base_name = re.sub(r'^BPF_', '', node_func_name).lower()
        imm = Imm(call_node.text, base_name=imm_base_name, insn=True)
        return d('.8byte {imm};')

    text = call_node.text.replace('\n', ' ')
    logging.warning(f"Can't convert {text}")
    if is_debug():
        with io.StringIO() as msg:
            msg.write("\n")
            msg.write("Errors:\n")
            for fn, e in errors:
                msg.write(f"  {fn.__name__:<30}: {e}\n")
            msg.write(f"Parse tree:\n")
            msg.write(pptree(call_node))
            logging.debug(msg.getvalue())
    return d('NOT CONVERTED: {text}')

#################################
##### Test case matching    #####
#################################

def convert_int_list(node):
    node.mtype('initializer_list')
    ints = []
    for item in node.mtype('initializer_list').named_children:
        ints.append(int(item.mtype('number_literal').text))
    return ints

SEC_BY_PROG_TYPE = {
    'BPF_PROG_TYPE_CGROUP_SKB'             : 'cgroup/skb',
    'BPF_PROG_TYPE_CGROUP_SOCK'            : 'cgroup/sock',
    # 'BPF_PROG_TYPE_CGROUP_SOCK_ADDR': '',
    'BPF_PROG_TYPE_CGROUP_SYSCTL'          : 'cgroup/sysctl',
    'BPF_PROG_TYPE_KPROBE'                 : 'kprobe',
    'BPF_PROG_TYPE_LSM'                    : 'lsm',
    'BPF_PROG_TYPE_LWT_IN'                 : 'lwt_in',
    'BPF_PROG_TYPE_LWT_OUT'                : 'lwt_out',
    'BPF_PROG_TYPE_LWT_XMIT'               : 'lwt_xmit',
    'BPF_PROG_TYPE_PERF_EVENT'             : 'perf_event',
    'BPF_PROG_TYPE_RAW_TRACEPOINT'         : 'raw_tracepoint',
    'BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE': 'raw_tracepoint.w',
    'BPF_PROG_TYPE_SCHED_ACT'              : 'action',
    'BPF_PROG_TYPE_SCHED_CLS'              : 'tc',
    'BPF_PROG_TYPE_SK_LOOKUP'              : 'sk_lookup',
    'BPF_PROG_TYPE_SK_MSG'                 : 'sk_msg',
    'BPF_PROG_TYPE_SK_REUSEPORT'           : 'sk_reuseport',
    'BPF_PROG_TYPE_SK_SKB'                 : 'sk_skb',
    'BPF_PROG_TYPE_SOCKET_FILTER'          : 'socket',
    'BPF_PROG_TYPE_SOCK_OPS'               : 'sockops',
    'BPF_PROG_TYPE_TRACEPOINT'             : 'tracepoint',
    # TODO: 'BPF_PROG_TYPE_TRACING': '',
    'BPF_PROG_TYPE_XDP'                    : 'xdp',
}

class Verdict(Enum):
    ACCEPT = 1
    REJECT = 2
    VERBOSE_ACCEPT = 3

class CommentsDict(dict):
    def __missing__(self, key):
        return None

class TestInfo:
    def __init__(self):
        self.name = None
        self.func_name = None
        self.insns = []
        self.map_fixups = {}
        self.result = Verdict.REJECT
        self.result_unpriv = None
        self.errstr = None
        self.errstr_unpriv = None
        self.retval = None
        self.retval_unpriv = None
        self.flags = []
        self.prog_type = None
        self.imms = {}
        self.kfunc_pairs = {}
        self.comments = CommentsDict()

def parse_test_result(node, field_name):
    match node.text:
        case 'ACCEPT':
            return Verdict.ACCEPT
        case 'VERBOSE_ACCEPT':
            return Verdict.VERBOSE_ACCEPT
        case 'REJECT':
            return Verdict.REJECT
        case _:
            logging.warning(f"Unsupported '{field_name}' value '{value.text}'")
            return None

def merge_comment_nodes(nodes):
    last_line = None
    with io.StringIO() as out:
        for n in nodes:
            if last_line and last_line != n.start_point[0]:
                out.write('\n')
            else:
                out.write(' ')
            out.write(n.text)
            last_line = n.end_point[0]
        return out.getvalue()

FLAGS_MAP = {
    'F_LOAD_WITH_STRICT_ALIGNMENT': 'BPF_F_STRICT_ALIGNMENT',
    'F_NEEDS_EFFICIENT_UNALIGNED_ACCESS': 'BPF_F_ANY_ALIGNMENT',
    }

def convert_insn_list(insns_to_convert, map_locations, kfunc_locations):
    insn_comments = []
    insns = []
    for insn in insns_to_convert:
        if insn.type == 'comment':
            insn_comments.append(insn)
        else:
            idx = len(insns)
            if idx in map_locations:
                pending_fixup = MapFixup()
            elif kfunc := kfunc_locations.get(idx, None):
                pending_fixup = KFuncFixup(kfunc)
            else:
                pending_fixup = None
            converted = convert_insn(insn, pending_fixup)
            if type(converted) != list:
                converted = [converted]
            converted[0].comment = merge_comment_nodes(insn_comments)
            for cinsn in converted:
                insns.append(cinsn)
                if getattr(cinsn, 'double_size', False):
                    dummy = DString('__dummy__', {})
                    dummy.dummy = True
                    insns.append(dummy)
            insn_comments = []
    if len(insns) > 0:
        insns[-1].after_comment = merge_comment_nodes(insn_comments)
    elif len(insn_comments) > 0:
        logging.warning(f'Dropping trailing comments {insn_comments} at {value}')
    return insns

def parse_kfunc_pairs(initializer_list):
    result = defaultdict(list)
    for pair in initializer_list.named_children:
        name = pair[0].mtype('string_literal').text.strip('"')
        idx = int(pair[1].mtype('number_literal').text)
        result[name].append(idx)
    return dict(result)

def match_test_info(node):
    node.mtype('initializer_list')
    elems = iter(node.named_children)
    info = TestInfo()
    pending_comments = []
    insns_to_convert = []

    while True:
        node = mnext(elems)
        match node.type:
            case 'comment':
                pending_comments.append(node)
            case 'string_literal':
                info.name = node.text
                info.comments['name'] = merge_comment_nodes(pending_comments)
                pending_comments = []
                break
            case _:
                raise MatchError(f'Expecting comment or string literal at {node}')
    while True:
        pair = next(elems, None)
        if pair is None:
            break
        if pair.type == 'comment':
            pending_comments.append(pair)
            continue
        pair.mtype('initializer_pair')
        field = pair['designator'][0].mtype('field_identifier').text
        value = pair['value']
        info.comments[field] = merge_comment_nodes(pending_comments)
        pending_comments = []
        # print(f'  field={field} value={value}')
        match field:
            case 'insns':
                insns_to_convert = value.mtype('initializer_list').named_children
            case 'errstr':
                info.errstr = value.text
            case 'errstr_unpriv':
                info.errstr_unpriv = value.text
            case 'result':
                info.result = parse_test_result(value, 'result')
            case 'result_unpriv':
                info.result_unpriv = parse_test_result(value, 'result_unpriv')
            case map_fixup if (map_name := map_fixup.removeprefix('fixup_')) in MAPS:
                info.map_fixups[map_name] = convert_int_list(value)
            case 'flags':
                text = value.mtype('identifier').text
                info.flags.append(FLAGS_MAP.get(text, text))
            case 'prog_type':
                info.prog_type = value.mtype('identifier').text
            case 'retval':
                info.retval = value.text
            case 'retval_unpriv':
                info.retval_unpriv = value.text
            case 'fixup_kfunc_btf_id':
                info.kfunc_pairs = parse_kfunc_pairs(value.mtype('initializer_list'))
            case _:
                logging.warning(f"Unsupported field '{field}' at {pair.start_point}:" +
                                f" {value.text}")
    map_locations = set()
    for locations in info.map_fixups.values():
        map_locations |= set(locations)
    kfunc_locations = {}
    for kfunc, locations in info.kfunc_pairs.items():
        for loc in locations:
            kfunc_locations[loc] = kfunc
    info.insns = convert_insn_list(insns_to_convert, map_locations, kfunc_locations)
    if pending_comments:
        logging.warning(f'Dropping pending comments {pending_comments}')
    return info

#################################
##### Instructions patching #####
#################################

def patch_ld_map_fd(text, map_name, test_name):
    if 'imm' in text.vars:
        text.vars['imm'] = Imm(f'&{map_name}')
    else:
        logging.warning(f'Unexpected insn to patch: {text} {map_name} {test_name}')
    return text

def replace_st_mem(insns):
    live_regs_map = cfg.compute_live_regs(insns)
    index_remap = []
    new_insns = []
    new_idx = 0
    #cfg.cfg_to_text(sys.stderr, cfg.build_cfg(insns), live_regs_map)
    for old_idx, insn in enumerate(insns):
        index_remap.append(len(new_insns))
        live_regs = live_regs_map[old_idx]
        if insn.st_mem and len(live_regs) < 9:
            free_reg = next(filter(lambda r: r not in live_regs, range(0, 10)))
            sz   = insn.vars['sz']
            dst  = insn.vars['dst']
            sign = insn.vars['sign']
            off  = insn.vars['off']
            imm  = insn.vars['imm']
            src  = f'r{free_reg}'   # TODO: should this be 'w' ?
            fst_insn = d('{src} = {imm};')
            snd_insn = d('*({sz}*)({dst} {sign} {off}) = {src};')
            if comment := getattr(insn, 'comment', None):
                fst_insn.comment = comment
            if comment := getattr(insn, 'after_comment', None):
                snd_insn.after_comment = comment
            new_insns.append(fst_insn)
            new_insns.append(snd_insn)
        else:
            new_insns.append(insn)
            if insn.st_mem:
                logging.warn(f"Can't infer free register for ST_MEM at {old_idx}")
    for old_idx, insn in enumerate(insns):
        if 'goto' not in insn.vars:
            continue
        old_target = old_idx + insn.vars['goto'] + 1
        new_idx    = index_remap[old_idx]
        if old_target < 0:
            new_target = old_target
        elif old_target >= len(insns):
            new_target = len(new_insns) + old_target - len(insns)
        else:
            new_target = index_remap[old_target]
        insn.vars['goto'] = new_target - new_idx - 1
    return new_insns

def insert_labels(insns, options):
    targets = {}
    # long labels are used for testing
    counter = options.label_start
    for i, insn in enumerate(insns):
        if isinstance(insn, str):
            print((i, insn))
        #print(f'{str(insn)}, {insn.template} {insn.vars}')
        if 'goto' not in insn.vars:
            continue
        target = i + insn.vars['goto'] + 1
        if target > len(insns) or target < 0:
            continue
        if target not in targets:
            targets[target] = f'l{counter}_%='
            counter += 1
        insn.vars['goto'] = targets[target]
    new_insns = []
    for i, insn in enumerate(insns):
        if i in targets:
            new_insns.append(DString(f'{targets[i]}:', {}))
        new_insns.append(insn)
    if after_end_label := targets.get(len(insns), None):
        new_insns.append(DString(f'{after_end_label}:', {}))
    return new_insns

KNOWN_IMM_MACRO_DEFS= set(['INT_MIN', 'LLONG_MIN',
                           'SHRT_MIN', 'SHRT_MAX',
                           'MAX_ENTRIES', 'EINVAL'])

def guess_imm_basename(imm):
    if imm.base_name:
        return imm.base_name, False
    text = imm.text
    if text in KNOWN_IMM_MACRO_DEFS:
        return text.lower(), False
    if m := re.match(r'^([\w\d]+)$', text):
        return m[1], False
    if m := re.match(r'^&([\w\d]+)$', text):
        return m[1], False
    if m := re.match(r'^sizeof\(struct ([\w\d]+)\)$', text):
        return f'sizeof_{m[1]}', False
    if m := re.match(r'^(offsetof|offsetofend)\(struct ([\w\d]+), ([\w\d]+)(\[[0-9]+\])?\)$',
                     text):
        suffix = ''
        if m[4]:
            suffix += "_" + m[4][1:-1]
        if m[1] == 'offsetofend':
            suffix += '__end'
        return f'{m[2]}_{m[3]}{suffix}', False
    return '__imm', True

def gen_imm_name(imm, counters):
    basename, force_counter = guess_imm_basename(imm)
    counter = counters.get(basename, 0)
    counters[basename] = counter + 1
    if counter > 0 or force_counter:
        return f'{basename}_{counter}'
    else:
        return basename

def rename_imms(insns):
    imm_to_name = {}
    counters = {}
    for insn in insns:
        for var_name, imm in insn.vars.items():
            if not isinstance(imm, Imm):
                continue
            if imm not in imm_to_name:
                imm_to_name[imm] = gen_imm_name(imm, counters)
            imm_name = imm_to_name[imm]
            insn.vars[var_name] = f'%[{imm_name}]'
    return imm_to_name

def format_imms(imm_to_name):
    imms = []
    for imm, name in imm_to_name.items():
        text = imm.text
        if imm.insn:
            imms.append(f'__imm_insn({name}, {text})')
        elif text == name:
            imms.append(f'__imm({name})')
        elif text == f'&{name}':
            imms.append(f'__imm_addr({name})')
        else:
            imms.append(f'__imm_const({name}, {text})')
    imms.sort()
    return ",\n\t  ".join(imms)

EXECUTABLE_PROG_TYPES = set([
    'BPF_PROG_TYPE_CGROUP_SKB'     , 'BPF_PROG_TYPE_FLOW_DISSECTOR',
    'BPF_PROG_TYPE_LWT_IN'         , 'BPF_PROG_TYPE_LWT_OUT',
    'BPF_PROG_TYPE_LWT_SEG6LOCAL'  , 'BPF_PROG_TYPE_LWT_XMIT',
    'BPF_PROG_TYPE_RAW_TRACEPOINT' , 'BPF_PROG_TYPE_SCHED_ACT',
    'BPF_PROG_TYPE_SCHED_CLS'      , 'BPF_PROG_TYPE_SK_LOOKUP',
    'BPF_PROG_TYPE_SOCKET_FILTER'  , 'BPF_PROG_TYPE_STRUCT_OPS',
    'BPF_PROG_TYPE_SYSCALL'        , 'BPF_PROG_TYPE_TRACING',
    'BPF_PROG_TYPE_XDP',
])

def patch_test_info(info, options):
    for map_name in info.map_fixups.keys():
        for i in info.map_fixups[map_name]:
            info.insns[i] = patch_ld_map_fd(info.insns[i], map_name, info.name)
    info.imms = rename_imms(info.insns)
    if options.replace_st_mem:
        info.insns = replace_st_mem(info.insns)
    info.insns = insert_labels(info.insns, options)
    if (not info.retval
        and info.result in [Verdict.ACCEPT, Verdict.VERBOSE_ACCEPT]
        and (info.prog_type in EXECUTABLE_PROG_TYPES
           # Default prog type is 'socket' which is executable
           or info.prog_type is None)):
        info.retval = '0'

###############################
##### C code generation   #####
###############################

def escape(text):
    # TODO: anything else to escape?
    escaped = text.replace('"', '\"')
    return escaped

ASM_LINE_WIDTH_IN_TABS = 7

def add_padding(text, num_tabs=ASM_LINE_WIDTH_IN_TABS):
    width_in_tabs = len(text.replace('\t', ' '*8)) // 8
    return text + '\t'*(num_tabs - width_in_tabs)

def format_insns(insns, newlines):
    if len(insns) == 0:
        return ''

    line_ending = ''
    if newlines:
        line_ending += '\\n'
    line_ending += '\\\n'

    def write_comment(text):
        if not text:
            return
        pfx = ''
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith('/*'):
                pfx = ''
            out.write(add_padding(f"\t{pfx}{line}"))
            out.write(line_ending)
            if line.startswith('/*'):
                pfx = ' '

    with StringIOWrapper() as out:
        label_line = False
        for i, insn in enumerate(insns):
            if getattr(insn, 'dummy', False):
                continue
            write_comment(getattr(insn, 'comment', None))
            text = escape(str(insn))
            is_label = text.endswith(':')
            if is_label:
                if len(text) < 8:
                    label_line = True
                    out.write(text)
                else:
                    label_line = False
                    text = add_padding(text)
                    out.write(text)
                    out.write(line_ending)
            else:
                label_line = False
                text = '\t' + text
                text = add_padding(text)
                out.write(text)
                out.write(line_ending)
            write_comment(getattr(insn, 'after_comment', None))
        if label_line:
            out.write(add_padding(""))
            out.write(line_ending)
        return out.getvalue()

def collect_attrs(info):
    def attrs_for_verdict(verdict, unpriv):
        sfx = '_unpriv' if unpriv else ''
        match verdict:
            case Verdict.ACCEPT:
                return f'__success{sfx}'
            case Verdict.VERBOSE_ACCEPT:
                return f'__success{sfx}'
            case Verdict.REJECT:
                return f'__failure{sfx}'

    attrs = []
    def attr(field, fn):
        if text := info.comments[field]:
            attrs.append(Comment(text))
        if val := getattr(info, field, None):
            match fn(val):
                case str(s):
                    attrs.append(s)
                case list(l):
                    attrs.extend(l)

    attr('name'         , lambda name  : f'__description({name})')
    attrs.append(Newline())
    attr('result'       , lambda result: attrs_for_verdict(result, False))
    attr('errstr'       , lambda errstr: f'__msg({errstr})')
    if info.prog_type in [None, 'BPF_PROG_TYPE_SOCKET_FILTER', 'BPF_PROG_TYPE_CGROUP_SKB']:
        if info.errstr:
            attrs.append(Newline())
        if (info.result_unpriv is None and info.errstr_unpriv is None):
            match info.result:
                case Verdict.ACCEPT | Verdict.VERBOSE_ACCEPT:
                    attrs.append('__success_unpriv')
                case Verdict.REJECT:
                    attrs.append('__failure_unpriv')
        else:
            attr('result_unpriv', lambda result: attrs_for_verdict(result, True))
            attr('errstr_unpriv', lambda errstr: f'__msg_unpriv({errstr})')
    attrs.append(Newline())
    if Verdict.VERBOSE_ACCEPT in [info.result, info.result_unpriv]:
        if Verdict.ACCEPT in [info.result, info.result_unpriv]:
            logging.warning(f'Log level differs between priv and unpriv for {info.name}')
        attrs.append('__log_level(2)')
    attr('retval'       , lambda retval: f'__retval({retval})')
    attr('retval_unpriv', lambda retval: f'__retval_unpriv({retval})')
    attr('flags'        , lambda flags : list(map(lambda flag: f'__flag({flag})', flags)))

    return attrs


class StringIOWrapper(io.StringIO):
    def __init__(self):
        super().__init__()
        self.last_is_newline = True

    def write(self, what):
        super().write(what)
        self.last_is_newline = what[-1] == "\n"

    def ensure_newline(self):
        if not self.last_is_newline:
            self.write("\n")

def render_attrs(attrs):
    with StringIOWrapper() as out:
        line_len = 0
        for attr in attrs:
            match attr:
                case Comment(text):
                    out.ensure_newline()
                    out.write(reindent_comment(text, 0))
                    out.ensure_newline()
                    line_len = 0
                case Newline():
                    out.ensure_newline()
                    line_len = 0
                case str(text):
                    if line_len + len(text) > 80:
                        out.ensure_newline()
                        line_len = 0
                    elif line_len != 0:
                        out.write(' ')
                        line_len += 1
                    out.write(text)
                    line_len += len(text)
        return out.getvalue().strip()

def reindent_comment(text, level, indent_at_end=True):
    if not text:
        return ''
    text = text.strip()
    indent = "\t" * level
    result = re.sub(r"\n\t*", "\n" + indent, text) + "\n"
    if indent_at_end:
        result += indent
    return result

def convert_prog_type(text):
    if text is None:
        return "socket"
    if text not in SEC_BY_PROG_TYPE:
        err = f'Unsupported prog_type {text}'
        logging.warning(err)
        return err
    return SEC_BY_PROG_TYPE[text]

def mk_func_base_name(text):
    text = text.lower()
    text = re.sub(r'[^\d\w]+', '_', text)
    text = text.strip('_')
    parts = text.split('_')[-5:]
    name = '_'.join(parts)
    if re.match('^\d', name):
        name = '_' + name
    return name

def assign_func_names(infos):
    all_names = defaultdict(list)
    for info in infos:
        base_name = mk_func_base_name(info.name)
        all_names[base_name].append(info)
    for name, infos in all_names.items():
        if len(infos) == 1:
            infos[0].func_name = name
        else:
            for i, info in enumerate(infos):
                info.func_name = f'{name}_{i+1}'

def render_test_info(info, options):
    if name_comment := info.comments.get('name', None):
        initial_comment = reindent_comment(name_comment, 0)
        info.comments['name'] = None
    else:
        initial_comment = ''
    asm_volatile=add_padding('asm volatile ("', 6) + '\\'
    attrs = collect_attrs(info)
    insns_comments = reindent_comment(info.comments['insns'], 1)
    insn_text = format_insns(info.insns, options.newlines)
    imms_text = format_imms(info.imms)
    sec = convert_prog_type(info.prog_type)
    if imms_text:
        tail = f'''
	: {imms_text}
	: __clobber_all
'''.rstrip()
    else:
        tail = ':: __clobber_all'

    return f'''
{initial_comment}SEC("{sec}")
{render_attrs(attrs)}
__naked void {info.func_name}(void)
{{
	{insns_comments}{asm_volatile}
{insn_text}"	:{tail});
}}
'''

def infer_includes(infos):
    extra = set()
    filterh = False
    for info in infos:
        for imm in info.imms:
            match imm.text:
                case 'INT_MIN' | 'LLONG_MIN':
                    extra.add('<limits.h>')
                case 'EINVAL':
                    extra.add('<errno.h>')
            if imm.insn:
                filterh = True
    includes = []
    includes.append('<linux/bpf.h>')
    includes.append('<bpf/bpf_helpers.h>')
    includes.extend(sorted(extra))
    if filterh:
        includes.append('"../../../include/linux/filter.h"')
    includes.append('"bpf_misc.h"')
    return includes

def infer_macros(infos):
    macros = set()
    for info in infos:
        for imm in info.imms:
            if imm.text.find('offsetofend') >= 0:
                macros.add('''
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \\
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
'''.lstrip())
    return list(sorted(macros))


def find_function_declarator(declaration):
    def recur(node):
        match node.type:
            case 'function_declarator':
                return node
            case 'declaration' | 'pointer_declarator':
                return recur(node['declarator'])
            case _:
                raise Exception(f'Unexpected node type: {node.type}')
    return recur(declaration)

@dataclass
class KFuncInfo:
    proto: str
    num_args: int
    deps: set

def scan_struct_deps(root_node):
    deps = set()
    def recur(node):
        match node.type:
            case 'struct_specifier':
                name = node["name"].text
                if name not in ['__sk_buff']:
                    deps.add(f'struct {name}')
            case _:
                for ch in node.named_children:
                    recur(ch)
    recur(root_node)
    return deps

def parse_kfunc_defs(text):
    defs = {}
    node = NodeWrapper(parse_c_string(text))
    for child in node.named_children:
        func = find_function_declarator(child)
        name = func['declarator'].mtype('identifier').text
        params = func['parameters'].named_children
        if len(params) == 1 and params[0].text == 'void':
            num_args = 0
        else:
            num_args = len(params)
        deps = scan_struct_deps(child)
        defs[name] = KFuncInfo(child.text, num_args, deps)
    return defs

KFUNCS_TEXT = '''
extern struct prog_test_member *bpf_kfunc_call_memb_acquire(void) __ksym;
extern struct prog_test_ref_kfunc *
	bpf_kfunc_call_test_acquire(unsigned long *scalar_ptr) __ksym;
extern struct prog_test_ref_kfunc *
	bpf_kfunc_call_test_kptr_get(struct prog_test_ref_kfunc **pp, int a, int b) __ksym;
extern void bpf_kfunc_call_memb1_release(struct prog_test_member1 *p) __ksym;
extern void bpf_kfunc_call_memb_release(struct prog_test_member *p) __ksym;
extern void bpf_kfunc_call_test_fail1(struct prog_test_fail1 *p) __ksym;
extern void bpf_kfunc_call_test_fail2(struct prog_test_fail2 *p) __ksym;
extern void bpf_kfunc_call_test_fail3(struct prog_test_fail3 *p) __ksym;
extern void bpf_kfunc_call_test_mem_len_fail1(void *mem, int len) __ksym;
extern void bpf_kfunc_call_test_pass_ctx(struct __sk_buff *skb) __ksym;
extern void bpf_kfunc_call_test_ref(struct prog_test_ref_kfunc *p) __ksym;
extern void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p) __ksym;
extern struct bpf_key *bpf_lookup_user_key(__u32 serial, __u64 flags) __ksym;
extern struct bpf_key *bpf_lookup_system_key(__u64 id) __ksym;
extern void bpf_key_put(struct bpf_key *key) __ksym;
'''

KFUNCS = parse_kfunc_defs(KFUNCS_TEXT)

MAPS = {
    'MAX_ENTRIES': {
        'deps': [],
        'text': '''
#define MAX_ENTRIES 11
'''},

    'test_val': {
        'deps': ['MAX_ENTRIES'],
        'text': '''
struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};
'''},

    'other_val': {
        'deps': [],
        'text': '''
struct other_val {
	long long foo;
	long long bar;
};
'''},

    'map_hash_48b': {
        'deps': ['test_val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct test_val);
} map_hash_48b SEC(".maps");
'''},

    'map_array_48b': {
        'deps': ['test_val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct test_val);
} map_array_48b SEC(".maps");
'''},

    'map_hash_16b': {
        'deps': ['other_val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct other_val);
} map_hash_16b SEC(".maps");
'''},

    'map_hash_8b': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, long long);
} map_hash_8b SEC(".maps");
'''},

    'cgroup_storage': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
	__uint(max_entries, 0);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, char[TEST_DATA_LEN]);
} cgroup_storage SEC(".maps");
'''},

    'percpu_cgroup_storage': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
	__uint(max_entries, 0);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, char[64]);
} percpu_cgroup_storage SEC(".maps");
'''},

    'map_xskmap': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} map_xskmap SEC(".maps");
'''},

    'map_array_small': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, char);
} map_array_small SEC(".maps");
'''},

    'map_reuseport_array': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} map_reuseport_array SEC(".maps");
'''},

    'map_ringbuf': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} map_ringbuf SEC(".maps");
'''},

    'map_sockhash': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} map_sockhash SEC(".maps");
'''},

    'map_sockmap': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} map_sockmap SEC(".maps");
'''},

    'map_stacktrace': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} map_stacktrace SEC(".maps");
'''},

    'map_array_ro': {
        'deps': ['test_val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct test_val);
	__uint(map_flags, BPF_F_RDONLY_PROG);
} map_array_ro SEC(".maps");
'''},

    'map_array_wo': {
        'deps': ['test_val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct test_val);
	__uint(map_flags, BPF_F_WRONLY_PROG);
} map_array_wo SEC(".maps");
'''},

    'val': {
        'deps': [],
        'text': '''
struct val {
	int cnt;
	struct bpf_spin_lock l;
};
'''},

    'timer': {
        'deps': [],
        'text': '''
struct timer {
	struct bpf_timer t;
};
'''},

    'map_spin_lock': {
        'deps': ['val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct val);
} map_spin_lock SEC(".maps");
'''},

    'map_in_map': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} map_in_map SEC(".maps");
'''},

    'map_timer': {
        'deps': ['timer'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer);
} map_timer SEC(".maps");
'''},

    'sk_storage_map': {
        'deps': ['val'],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(max_entries, 0);
	__type(key, int);
	__type(value, struct val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sk_storage_map SEC(".maps");
'''},

    'map_kptr': {
        'deps': [],
        'text': '''
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct btf_ptr);
} map_kptr SEC(".maps");
'''},

}

def print_map_definitions(out, used_maps):
    printed = set()

    def print_with_deps(name):
        if name in printed:
            return
        printed.add(name)
        desc = MAPS[name]
        for dep in desc['deps']:
            print_with_deps(dep)
        out.write(desc['text'])

    for m in sorted(used_maps):
        print_with_deps(m)

def print_kfunc_definitions(out, kfuncs):
    fake_calls = []
    protos = []
    deps = set()
    for kfunc in sorted(kfuncs):
        if kfunc not in KFUNCS:
            logging.warning(f'Unknown kfunc {kfunc}')
            continue
        info = KFUNCS[kfunc]
        protos.append(info.proto + '\n')
        args = ', '.join(["0"] * info.num_args)
        fake_calls.append(f'{kfunc}({args});')
        deps |= info.deps
    for dep in sorted(deps):
        out.write(f'{dep} {{}} __attribute__((preserve_access_index));\n')
    if deps:
        out.write('\n')
    for proto in protos:
        out.write(proto)
    out.write("\n")
    fake_calls_text = "\n\t".join(fake_calls)
    out.write(f'''
/* BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root()
{{
	{fake_calls_text}
}}
'''.lstrip())

def print_auxiliary_definitions(out, infos):
    used_maps = set()
    kfuncs = set()

    for info in infos:
        for map_name, fixups in info.map_fixups.items():
            if fixups:
                used_maps.add(map_name)
        kfuncs |= info.kfunc_pairs.keys()

    if kfuncs:
        out.write("\n")
        print_kfunc_definitions(out, kfuncs)
    if len(kfuncs) > 0 and len(used_maps) > 0:
        out.write("\n")
    if used_maps:
        print_map_definitions(out, used_maps)

@dataclass
class Options:
    newlines: bool = False
    replace_st_mem: bool = False
    discard_prefix: str = ''
    blacklist: list = ()
    whitelist: list = ()
    label_start: int = 0

@dataclass
class Comment:
    text: str

@dataclass
class Newline:
    pass

@dataclass
class TestCase:
    info: TestInfo

def convert_translation_unit(root_node, options):
    query = C_LANGUAGE.query('''
      (translation_unit
        (declaration
          (struct_specifier)
          (init_declarator
            (array_declarator)
            (initializer_list) @tests)))''')
    captures = query.captures(root_node)
    # pptree(node)
    # print(captures)
    assert len(captures) == 1
    entries = []
    for test_node in map(NodeWrapper, captures[0][0].named_children):
        if test_node.type == 'comment':
            entries.append(Comment(test_node.text))
        else:
            try:
                info = match_test_info(test_node)
                skip = False
                if options.blacklist:
                    skip = any(map(lambda r: re.search(r, info.name), options.blacklist))
                if not skip and options.whitelist:
                    skip = not any(map(lambda r: re.search(r, info.name), options.whitelist))
                if skip:
                    logging.warning(f'skipping {info.name}')
                    continue
                entries.append(TestCase(info))
            except MatchError as error:
                short_text = test_node.text[0:40]
                logging.warning(f"""
Can't convert test case:
  Location: {test_node.start_point} '{short_text}...'
  Error   : {error}
""")
    infos=list(map(lambda e: e.info,
                   filter(lambda e: isinstance(e, TestCase), entries)))
    for info in infos:
        patch_test_info(info, options)
    includes = infer_includes(infos)
    macros = infer_macros(infos)
    assign_func_names(infos)

    with io.StringIO() as out:
        for include in includes:
            out.write(f'#include {include}\n')
        if macros:
            out.write('\n')
        for macro in macros:
            out.write(macro)
        print_auxiliary_definitions(out, infos)
        for entry in entries:
            match entry:
                case TestCase(info):
                    out.write(render_test_info(info, options))
                case Comment(text):
                    out.write("\n")
                    out.write(text)
                    out.write("\n")
        out.write('\n')
        out.write('char _license[] SEC("license") = "GPL";\n')
        return out.getvalue()

###############################
#####    Entry points     #####
###############################

def convert_string(full_text, options):
    fake_input = 'struct foo x[] = {' + "\n" + full_text + "\n" + '};'
    root_node = parse_c_string(fake_input)
    return convert_translation_unit(root_node, options)

def convert_file(file_name, options):
    with open(file_name, 'r') as f:
        short_name = file_name.removeprefix(options.discard_prefix)
        print( '// SPDX-License-Identifier: GPL-2.0')
        print(f'/* Converted from {short_name} */')
        print()
        print(convert_string(f.read(), options))

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--debug', action=argparse.BooleanOptionalAction)
    p.add_argument('--newlines', action=argparse.BooleanOptionalAction)
    p.add_argument('--replace-st-mem', action=argparse.BooleanOptionalAction)
    p.add_argument('file_name', type=str)
    p.add_argument('--discard-prefix', type=str, default='')
    blacklist = []
    whitelist = []
    p.add_argument('--blacklist', action='append', default=blacklist)
    p.add_argument('--whitelist', action='append', default=whitelist)
    args = p.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, force=True)
    convert_file(args.file_name, Options(newlines=args.newlines,
                                         replace_st_mem=args.replace_st_mem,
                                         discard_prefix=args.discard_prefix,
                                         blacklist=args.blacklist,
                                         whitelist=args.whitelist))

# TODO:
# - preserve comments
