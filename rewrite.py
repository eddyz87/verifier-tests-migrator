#!/usr/bin/python3

import os
import io
import re
import sys
import cfg
import copy
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

    def number(self):
        arg = self._next_arg()
        text = arg.mtype('number_literal').text
        return text_to_int(text)

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
        insn.size = 2
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
            insn.size = 2
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
        r = d('call {goto};')
        r.pseudocall = True
        return r

    def BPF_RAW_INSN___bpf_call(m):
        m.jmp_call()
        m.zero()
        m.one()
        m.zero()
        goto = m.number()
        r = d('call {goto};')
        r.pseudocall = True
        return r

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

    def BPF_ENDIAN(m):
        kind = m._ident()
        match kind:
            case 'BPF_TO_LE' | 'BPF_FROM_LE':
                pfx = 'le'
            case 'BPF_TO_BE' | 'BPF_FROM_BE':
                pfx = 'be'
            case _:
                raise MatchError(f'Unexpected endian kind: {kind}')
        dst = m.reg()
        sz = m.number()
        if sz not in [16, 32, 64]:
            raise MatchError(f'Unexpected endian size: {sz}')
        op = f'{pfx}{sz}'
        return d('{dst} = {op} {dst};', 'rw')

    def BPF_SK_LOOKUP(m):
        func = m._ident()
        func = Imm(f'bpf_{func}')
        insn = d('BPF_SK_LOOKUP({func})')
        insn.vars['imm1'] = Imm('sizeof(struct bpf_sock_tuple)')
        insn.size = 13
        insn.macro = 'BPF_SK_LOOKUP'
        insn.call_like = True
        return insn

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

@dataclass
class SecInfo:
    base_name: str
    may_sleep: bool = False
    need_kfunc: bool = False

SEC_BY_PROG_AND_ATTACH_TYPE = {
    ('BPF_PROG_TYPE_CGROUP_SOCK_ADDR', 'BPF_CGROUP_INET4_CONNECT'  ): SecInfo("cgroup/connect4"),
    ('BPF_PROG_TYPE_CGROUP_SOCK'     , 'BPF_CGROUP_INET4_POST_BIND'): SecInfo("cgroup/post_bind4"),
    ('BPF_PROG_TYPE_CGROUP_SOCKOPT'  , 'BPF_CGROUP_SETSOCKOPT'     ): SecInfo("cgroup/setsockopt"),
    ('BPF_PROG_TYPE_CGROUP_SOCK_ADDR', 'BPF_CGROUP_UDP6_SENDMSG'   ): SecInfo("cgroup/sendmsg6"),
    ('BPF_PROG_TYPE_SK_LOOKUP'       , 'BPF_SK_LOOKUP'             ): SecInfo("sk_lookup"),
    ('BPF_PROG_TYPE_LSM'             , 'BPF_LSM_MAC'               ): SecInfo("lsm"     , True, True),
    ('BPF_PROG_TYPE_TRACING'         , 'BPF_MODIFY_RETURN'         ): SecInfo("fmod_ret", True, True),
    ('BPF_PROG_TYPE_TRACING'         , 'BPF_TRACE_FENTRY'          ): SecInfo("fentry"  , True, True),
    ('BPF_PROG_TYPE_TRACING'         , 'BPF_TRACE_ITER'            ): SecInfo("iter"    , True, True),
    ('BPF_PROG_TYPE_TRACING'         , 'BPF_TRACE_RAW_TP'          ): SecInfo("tp_btf"  , False, True),
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
        self.prog_fixups = {}
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
        self.sleepable = False
        self.expected_attach_type = None
        self.kfunc = None
        self.sec = None
        self.insn_processed = None
        self.dont_run = False

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
                if sz := getattr(cinsn, 'size', 1):
                    for _ in range(0, sz-1):
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

def parse_flags(text):
    sleepable = False
    flag = None
    match text:
        case 'BPF_F_SLEEPABLE':
            sleepable = True
        case 'F_LOAD_WITH_STRICT_ALIGNMENT':
            flag = 'BPF_F_STRICT_ALIGNMENT'
        case 'F_NEEDS_EFFICIENT_UNALIGNED_ACCESS':
            flag = 'BPF_F_ANY_ALIGNMENT'
        case 'BPF_F_TEST_STATE_FREQ':
            flag = text
        case _:
            logging.warning(f'Unsupported .flag: {text}')
    return flag, sleepable

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
            case 'fixup_prog1':
                info.prog_fixups['map_prog1'] = convert_int_list(value)
            case 'fixup_prog2':
                info.prog_fixups['map_prog2'] = convert_int_list(value)
            case 'flags':
                text = value.mtype('identifier').text
                flag, sleepable = parse_flags(text)
                if flag:
                    info.flags = [flag]
                info.sleepable = sleepable
            case 'prog_type':
                info.prog_type = value.mtype('identifier').text
            case 'retval':
                info.retval = value.text
            case 'retval_unpriv':
                info.retval_unpriv = value.text
            case 'fixup_kfunc_btf_id':
                info.kfunc_pairs = parse_kfunc_pairs(value.mtype('initializer_list'))
            case 'expected_attach_type':
                info.expected_attach_type = value.mtype('identifier').text
            case 'kfunc':
                info.kfunc = value.mtype('string_literal').text.strip('"')
            case 'insn_processed':
                info.insn_processed = value.text
            case 'runs' if value.text == '-1':
                info.dont_run = True
            case _:
                logging.warning(f"Unsupported field '{field}' at {pair.start_point}:" +
                                f" {value.text}")

    info.sec = convert_prog_type(info)
    map_locations = set()
    for locations in info.map_fixups.values():
        map_locations |= set(locations)
    for locations in info.prog_fixups.values():
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
    if m := re.match(r'^sizeof\(struct\s+([\w\d]+)\)$', text):
        return f'sizeof_{m[1]}', False
    if m := re.match(r'^(offsetof|offsetofend)\(struct ([\w\d]+),\s*([\w\d]+)(\[[0-9]+\])?\)$',
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
            if getattr(insn, 'macro', False):
                insn.vars[var_name] = imm_name
            else:
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
            text = re.sub(r'\s+', ' ', imm.text)
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
    def patch_locations(map_name, locations):
        for i in locations:
            info.insns[i] = patch_ld_map_fd(info.insns[i], map_name, info.name)

    for map_name, locations in info.map_fixups.items():
        patch_locations(map_name, locations)

    for map_name, locations in info.prog_fixups.items():
        true_map_name = f'{map_name}_{info.sec}'
        patch_locations(true_map_name, locations)

    if options.replace_st_mem:
        info.insns = replace_st_mem(info.insns)
    if (not info.retval
        and info.result in [Verdict.ACCEPT, Verdict.VERBOSE_ACCEPT]
        and (info.prog_type in EXECUTABLE_PROG_TYPES
           # Default prog type is 'socket' which is executable
           or info.prog_type is None)
        and not info.dont_run):
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

# Filter out a bunch of unnecessary comments coming from
# tools/testing/selftests/bpf/verifier/spill_fill.c
def similar_strings(a, b):
    def simplify(s):
        s = s.strip()
        s = re.sub(r'\s+', '', s)
        s = s.removeprefix('/*')
        s = s.removesuffix('*/')
        s = s.removesuffix(';')
        s = s.removesuffix(',')
        s = re.sub(r'w([0-9]+)', lambda m: 'r' + m[1], s)
        s = re.sub(r'u(8|16|32|64)', 'uXX', s)
        return s

    return simplify(a) == simplify(b)

def format_insns(insns, options):
    if len(insns) == 0:
        return '""'

    first_line = True
    quotes_open = False
    line_ending = ''
    if options.newlines:
        line_ending += '\\n'
    line_ending += '\\\n'

    def ensure_quotes():
        nonlocal first_line
        nonlocal quotes_open
        nonlocal line_ending
        if not quotes_open:
            quotes_open = True
            if first_line:
                out.write(add_padding('"', 5))
                out.write(line_ending)
                first_line = False
            else:
                out.write('"')

    def close_quotes():
        nonlocal first_line
        nonlocal quotes_open
        if quotes_open:
            quotes_open = False
            out.write('"')
        elif first_line:
            out.write('\n')
            first_line = False

    with StringIOWrapper() as out:
        def write_line(text, is_comment=False, is_macro=False):
            if options.string_per_insn:
                nonlocal first_line
                if first_line:
                    out.write('\n')
                    first_line = False
                if not is_comment:
                    m = re.match(r'^(\t?)(.*)$', text)
                    if is_macro:
                        text = f'{m[1]}{m[2]}'
                    else:
                        text = f'{m[1]}"{m[2]}"'
                out.write(text)
                out.write('\n')
            else:
                if is_macro:
                    close_quotes()
                    out.write(text)
                    out.write('\n')
                else:
                    ensure_quotes()
                    out.write(add_padding(text))
                    out.write(line_ending)

        def write_comment(text, insn_text):
            if not text:
                return
            if similar_strings(text, insn_text):
                return
            pfx = ''
            for line in text.split('\n'):
                line = line.strip()
                if line.startswith('/*'):
                    pfx = ''
                write_line(f"\t{pfx}{line}", is_comment=True)
                if line.startswith('/*'):
                    pfx = ' '

        label_line = False
        for i, insn in enumerate(insns):
            if getattr(insn, 'dummy', False):
                continue
            text = escape(str(insn))
            write_comment(getattr(insn, 'comment', None), text)
            is_label = text.endswith(':')
            if is_label:
                if len(text) < 7 and not options.string_per_insn:
                    label_line = True
                    ensure_quotes()
                    out.write(text)
                else:
                    label_line = False
                    write_line(text)
            else:
                label_line = False
                write_line('\t' + text, is_macro=getattr(insn, 'macro', False))
            write_comment(getattr(insn, 'after_comment', None), text)
        if label_line:
            write_line("")
        close_quotes()
        return out.getvalue()

def convert_prog_type(info):
    prog_type = info.prog_type
    attach_type = info.expected_attach_type

    def error(err = None):
        if not err:
            nonlocal prog_type, attach_type
            err = f'Unsupported prog_type / attach_type combo: {prog_type} / {attach_type}'
        logging.warning(err)
        return err

    if not prog_type and not attach_type:
        return "socket"

    if prog_type and not attach_type:
        if prog_type not in SEC_BY_PROG_TYPE:
            return error()
        return SEC_BY_PROG_TYPE[prog_type]

    if sec := SEC_BY_PROG_AND_ATTACH_TYPE.get((prog_type, attach_type), None):
        acc = sec.base_name

        if info.sleepable:
            if not sec.may_sleep:
                return error(f'{prog_type}/{attach_type} may not sleep');
            acc += ".s"

        if sec.need_kfunc:
            if not info.kfunc:
                return error(f'{prog_type}/{attach_type} need kfunc')
            acc += "/"
            acc += info.kfunc

        return acc

    return error()

OK_FOR_UNPRIV_PROG_TYPES = [None, 'BPF_PROG_TYPE_SOCKET_FILTER', 'BPF_PROG_TYPE_CGROUP_SKB']
OK_FOR_UNPRIV_SECS = []
for tp in OK_FOR_UNPRIV_PROG_TYPES:
    info = TestInfo()
    info.prog_type = tp
    OK_FOR_UNPRIV_SECS.append(convert_prog_type(info))

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
    attr('insn_processed', lambda insn_processed: f'__msg("processed {insn_processed} insns")')
    if info.prog_type in OK_FOR_UNPRIV_PROG_TYPES:
        if info.errstr or info.insn_processed:
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
        if info.insn_processed and not info.errstr_unpriv:
            attrs.append('__msg_unpriv("")')
    if info.errstr or info.errstr_unpriv:
        attrs.append(Newline())
    if Verdict.VERBOSE_ACCEPT in [info.result, info.result_unpriv]:
        if Verdict.ACCEPT in [info.result, info.result_unpriv]:
            logging.warning(f'Log level differs between priv and unpriv for {info.name}')
        attrs.append('__log_level(2)')
    elif info.insn_processed:
        attrs.append('__log_level(1)')
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

def collect_imms(insns):
    imms = []
    for insn in insns:
        for imm in insn.vars.values():
            if not isinstance(imm, Imm):
                continue
            imms.append(imm)
    return imms

def copy_comments(new_insn, old_insn):
    if c := getattr(old_insn, 'comment', None):
        new_insn.comment = c
    if c := getattr(old_insn, 'after_comment', None):
        new_insn.after_comment = c
    return new_insn

def slice_into_functions(name, insns):
    if len(insns) == 0:
        return [insns]

    call_targets = { 0: 0 }
    for i, insn in enumerate(insns):
        if not getattr(insn, 'pseudocall', False):
            continue
        target = i + insn.vars['goto'] + 1
        if target not in call_targets:
            call_targets[target] = len(call_targets)
    err = False
    for target in call_targets:
        if target >= len(insns) or target < 0:
            logging.warning(f'{name}: invalid pseudocall target {target}')
            err = True
            continue
        if getattr(insns[target], 'dummy', False):
            logging.warning(f'{name}: pseudocall target in the middle of double insn {target}')
            err = True
    if err:
        return [insns]

    funcs = []
    for i, insn in enumerate(insns):
        if i in call_targets:
            funcs.append([])
        if getattr(insn, 'pseudocall', False):
            target = i + insn.vars['goto'] + 1
            local_func = call_targets[target]
            new_insn = d('call {local_func}')
            new_insn.pseudocall = True
            insn = copy_comments(new_insn, insn)
        funcs[-1].append(insn)
    func_start = 0
    for func in funcs:
        for i, insn in enumerate(func):
            if 'goto' not in insn.vars or getattr(insn, 'pseudocall', False):
                continue
            target = i + insn.vars['goto'] + 1
            if target >= len(insns) or target < 0:
                logging.warning(f'{name}: goto outside of a function at {i + func_start}')
                err = True
        func_start += len(func)

    if err:
        return [insns]

    return funcs

def rename_local_funcs(base_name, insns):
    new_insns = []
    for insn in insns:
        if 'local_func' in insn.vars:
            local_func = insn.vars['local_func']
            if local_func == 0:
                text = f'call {base_name};'
            else:
                text = f'call {base_name}__{local_func};'
            insn = copy_comments(DString(text, {}), insn)
        new_insns.append(insn)
    return new_insns

def render_func(base_name, name, insns, main, insns_comments, options):
    insns = rename_local_funcs(base_name, insns)
    insns = insert_labels(insns, options)
    imms = rename_imms(insns)
    insn_text = format_insns(insns, options)
    tail_pfx  = ' ' if insn_text == '""' else '\t'
    imms_text = format_imms(imms)
    noinline_text = "" if main else "__noinline "
    if main:
        attrs = "__naked "
    else:
        attrs = "static __naked __noinline __attribute__((used))\n"
    if imms_text:
        tail = f'''
	: {imms_text}
	: __clobber_all
'''.rstrip()
    else:
        tail = ':: __clobber_all'

    return f'''
{attrs}void {name}(void)
{{
	{insns_comments}asm volatile ({insn_text}{tail_pfx}:{tail});
}}
'''.lstrip()

def render_test_info(info, options):
    funcs = slice_into_functions(info.name, info.insns)
    rendered_funcs = []
    for i, func in enumerate(funcs):
        main = i == 0
        rendered_funcs.append(render_func(
            base_name = info.func_name,
            name = info.func_name if main else f'{info.func_name}__{i}',
            insns = func,
            main = main,
            insns_comments = reindent_comment(info.comments['insns'], 1),
            options = options
        ))
    if name_comment := info.comments.get('name', None):
        initial_comment = reindent_comment(name_comment, 0)
        info.comments['name'] = None
    else:
        initial_comment = ''
    attrs = collect_attrs(info)
    rendered_funcs[0] = f'''
{initial_comment}SEC("{info.sec}")
{render_attrs(attrs)}
{rendered_funcs[0].strip()}
'''.lstrip()
    return "\n" + "\n".join(rendered_funcs)

def infer_includes(infos):
    extra = set()
    filterh = False
    for info in infos:
        for imm in collect_imms(info.insns):
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
        for imm in collect_imms(info.insns):
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

MACRO_DEFS = {
    'BPF_SK_LOOKUP': '''
#define BPF_SK_LOOKUP(func) \\
	/* struct bpf_sock_tuple tuple = {} */ \\
	"r2 = 0;"			\\
	"*(u32*)(r10 - 8) = r2;"	\\
	"*(u64*)(r10 - 16) = r2;"	\\
	"*(u64*)(r10 - 24) = r2;"	\\
	"*(u64*)(r10 - 32) = r2;"	\\
	"*(u64*)(r10 - 40) = r2;"	\\
	"*(u64*)(r10 - 48) = r2;"	\\
	/* sk = func(ctx, &tuple, sizeof tuple, 0, 0) */ \\
	"r2 = r10;"			\\
	"r2 += -48;"			\\
	"r3 = %[sizeof_bpf_sock_tuple];"\\
	"r4 = 0;"			\\
	"r5 = 0;"			\\
	"call %[" #func "];"
'''.lstrip()
}

def print_macro_definitions(out, macros):
    for macro in macros:
        out.write('\n')
        out.write(MACRO_DEFS[macro].lstrip())

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

def print_prog_map_definitions(out, used_prog_maps):
    secs = {}
    for map_name, sec in used_prog_maps:
        if sec not in secs:
            secs[sec] = set()
        secs[sec].add(map_name)

    for sec, map_names in secs.items():
        prog1 = 'map_prog1' in map_names
        prog2 = 'map_prog2' in map_names
        suffix = f'_{sec}'
        if sec in OK_FOR_UNPRIV_SECS:
            auxiliary_unpriv = ' __auxiliary_unpriv'
        else:
            auxiliary_unpriv = ''

        out.write(f'''
void dummy_prog_42{suffix}(void);
void dummy_prog_24{suffix}(void);
'''.lstrip())

        if prog1:
            out.write(f'''
void dummy_prog_loop1{suffix}(void);
'''.lstrip())

        if prog2:
            out.write(f'''
void dummy_prog_loop2{suffix}(void);
'''.lstrip())

        if prog1:
            out.write(f'''
struct {{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__uint(key_size, sizeof(int));
	__array(values, void (void));
}} map_prog1{suffix} SEC(".maps") = {{
	.values = {{
		[0] = (void *) &dummy_prog_42{suffix},
		[1] = (void *) &dummy_prog_loop1{suffix},
		[2] = (void *) &dummy_prog_24{suffix},
	}},
}};
''')

        if prog2:
            out.write(f'''
struct {{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 8);
	__uint(key_size, sizeof(int));
	__array(values, void (void));
}} map_prog2{suffix} SEC(".maps") = {{
	.values = {{
		[1] = (void *) &dummy_prog_loop2{suffix},
		[2] = (void *) &dummy_prog_24{suffix},
		[7] = (void *) &dummy_prog_42{suffix},
	}},
}};
''')

        out.write(f'''
SEC("{sec}")
__auxiliary{auxiliary_unpriv}
__naked void dummy_prog_42{suffix}(void) {{
	asm volatile ("r0 = 42; exit;");
}}

SEC("{sec}")
__auxiliary{auxiliary_unpriv}
__naked void dummy_prog_24{suffix}(void) {{
	asm volatile ("r0 = 24; exit;");
}}
''')

        def dummy_prog_loop(self_name, map_name):
            out.write(f'''
SEC("{sec}")
__auxiliary{auxiliary_unpriv}
__naked void {self_name}(void) {{
	asm volatile ("			\\
	r3 = 1;				\\
	r2 = %[{map_name}] ll;	\\
	call %[bpf_tail_call];		\\
	r0 = 41;			\\
	exit;				\\
"	:
	: __imm(bpf_tail_call),
	  __imm_addr({map_name})
	: __clobber_all);
}}
''')

        if prog1:
            dummy_prog_loop(f'dummy_prog_loop1{suffix}', f'map_prog1{suffix}')
        if prog2:
            dummy_prog_loop(f'dummy_prog_loop2{suffix}', f'map_prog2{suffix}')

def print_auxiliary_definitions(out, infos):
    used_prog_maps = set()
    used_maps = set()
    kfuncs = set()
    macros = set()

    for info in infos:
        for map_name, fixups in info.map_fixups.items():
            if fixups:
                used_maps.add(map_name)
        for map_name, fixups in info.prog_fixups.items():
            if fixups:
                used_prog_maps.add((map_name, info.sec))
        kfuncs |= info.kfunc_pairs.keys()
        for insn in info.insns:
            if m := getattr(insn, 'macro', None):
                macros.add(m)

    if macros:
        print_macro_definitions(out, macros)

    if kfuncs:
        out.write('\n')
        print_kfunc_definitions(out, kfuncs)

    if used_maps:
        print_map_definitions(out, used_maps)

    if used_prog_maps:
        out.write('\n')
        print_prog_map_definitions(out, used_prog_maps)

@dataclass
class Options:
    newlines: bool = False
    string_per_insn: bool = False
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
        out.write('char _license[] SEC("license") = "GPL";')
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
    p.add_argument('--string-per-insn', action=argparse.BooleanOptionalAction)
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
                                         string_per_insn=args.string_per_insn,
                                         discard_prefix=args.discard_prefix,
                                         blacklist=args.blacklist,
                                         whitelist=args.whitelist))

# TODO:
# - preserve comments
