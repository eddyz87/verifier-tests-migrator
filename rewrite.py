#!/usr/bin/python3

import io
import re
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
        print(out.getvalue())

#################################
##### Instructions matching #####
#################################

@dataclass
class Imm:
    text: str

class CallMatcher:
    imm_counter = 0

    def __init__(self, node):
        node.mtype('call_expression')
        self._args = iter(node['arguments'].named_children)

    def _next_arg(self):
        try:
            return next(self._args)
        except StopIteration:
            raise MatchError()

    def _ident(self):
        return self._next_arg().mtype('identifier').text

    def ensure_args_consumed(self):
        try:
            next(self._args)
            raise MatchError()
        except StopIteration:
            pass

    def _regno(self):
        arg = self._next_arg()

        def _regno_ident():
            m = re.match(r'^BPF_REG_([0-9]+)$', arg.mtype('identifier').text)
            if m is None:
                raise MatchError()
            return m[1]

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
        ident = self._ident()
        if ident == 'BPF_DW':
            return 'u64'
        elif ident == 'BPF_W':
            return 'u32'
        elif ident == 'BPF_B':
            return 'u8'
        else:
            raise MatchError()

    def _intern_expr(self, node):
        if node.type == 'number_literal':
            return node.text
        return Imm(node.text)

    def expr(self):
        return self._intern_expr(self._next_arg())

    def off(self):
        arg = self._next_arg()
        text = self._intern_expr(arg)
        if arg.type == 'number_literal' and not re.match(r'^[+-]', text):
            return f'+{text}'
        return text

    def number(self):
        text = self._next_arg().mtype('number_literal').text
        if text.startswith('0x'):
            return int(text, 16)
        else:
            return int(text)

    def bpf_func_ident(self):
        raw_func = self._ident()
        func_match = re.match(r'BPF_FUNC_(.+)', raw_func)
        if not func_match:
            raise MatchError(d('Strange func name {raw_func}'))
        return Imm(f'bpf_{func_match[1]}')

    _ALU_OPS = {
        'BPF_ADD': '+= ',
        'BPF_SUB': '-= ',
        'BPF_MUL': '*= ',
        'BPF_DIV': '/= ',
        'BPF_MOD': '%= ',
        'BPF_OR' : '|= ',
        'BPF_AND': '&= ',
        'BPF_LSH': '<<= ',
        'BPF_RSH': '>>= ',
        'BPF_XOR': '^= ',
        'BPF_SRA': 's>>= ',
        'BPF_NEG': '= -',
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
        return d('{dst} = {src};')

    def BPF_ALU64_IMM(m):
        op = m.alu_op()
        dst = m.reg()
        imm = m.expr()
        return d('{dst} {op}{imm};')

    def BPF_ALU32_IMM(m):
        op = m.alu_op()
        dst = m.reg32()
        imm = m.expr()
        return d('{dst} {op}{imm};')

    def BPF_ALU64_REG(m):
        op = m.alu_op()
        dst = m.reg()
        src = m.reg()
        return d('{dst} {op}{src};')

    def BPF_ALU32_REG(m):
        op = m.alu_op()
        dst = m.reg32()
        src = m.reg32()
        return d('{dst} {op}{src};')

    def BPF_MOV64_IMM(m):
        dst = m.reg()
        imm = m.expr()
        return d('{dst} = {imm};')

    def BPF_MOV32_IMM(m):
        dst = m.reg32()
        imm = m.expr()
        return d('{dst} = {imm};')

    def BPF_LD_IMM64(m):
        dst = m.reg()
        imm = m.expr()
        return d('{dst} = {imm} ll;')

    def BPF_LDX_MEM(m):
        sz = m.size()
        dst = m.reg()
        src = m.reg()
        off = m.off()
        return d('{dst} = *({sz}*)({src} {off});')

    def BPF_ST_MEM(m):
        sz = m.size()
        dst = m.reg()
        off = m.off()
        imm = m.expr()
        return d('*({sz}*)({dst} {off}) = {imm};')

    def BPF_STX_MEM(m):
        sz = m.size()
        dst = m.reg()
        src = m.reg()
        off = m.off()
        return d('*({sz}*)({dst} {off}) = {src};')

    def BPF_LD_MAP_FD(m):
        dst = m.reg()
        imm = m.expr()
        return d('{dst} = {imm} ll;')

    def BPF_JMP_IMM(m):
        op = m.jmp_op()
        dst = m.reg()
        imm = m.expr()
        goto = m.number()
        return d('if {dst} {op} {imm} goto {goto};')

    def BPF_JMP32_IMM(m):
        op = m.jmp_op()
        dst = m.reg32()
        imm = m.expr()
        goto = m.number()
        return d('if {dst} {op} {imm} goto {goto};')

    def BPF_JMP_REG(m):
        op = m.jmp_op()
        dst = m.reg()
        src = m.reg()
        goto = m.number()
        return d('if {dst} {op} {src} goto {goto};')

    def BPF_JMP32_REG(m):
        op = m.jmp_op()
        dst = m.reg32()
        src = m.reg32()
        goto = m.number()
        return d('if {dst} {op} {src} goto {goto};')

    def BPF_JMP_IMM___goto(m):
        m._next_arg().mtype('identifier').mtext('BPF_JA')
        m.zero()
        m.zero()
        goto = m.number()
        return d('goto {goto};')

    def BPF_EXIT_INSN(m):
        return d('exit;')

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

def convert_insn(call_node):
    if is_debug():
        logging.debug('convert_insn: %s', call_node.text)
        pptree(call_node)
    for fn in FUNC_MATCHERS[call_node['function'].text]:
        m = CallMatcher(call_node)
        try:
            result = fn(m)
            m.ensure_args_consumed()
            return result
        except MatchError as e:
            if is_debug() and e.args[0]:
                logging.debug(f'{name} no match: {e}')

    text = call_node.text.replace('\n', ' ')
    logging.warning(f"Can't convert {text}")
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

FLAGS = {
    'F_NEEDS_EFFICIENT_UNALIGNED_ACCESS': '__needs_efficient_unaligned_access',
}

def convert_flags(node):
    node.mtype('identifier')
    flag = node.text
    if flag not in FLAGS:
        raise MatchError(f'Unsupported flag {flag}')
    return [FLAGS[flag]]

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

def convert_prog_type(node):
    node.mtype('identifier')
    text = node.text
    if text not in SEC_BY_PROG_TYPE:
        raise MatchError(f'Unsupported prog_type {text}')
    return SEC_BY_PROG_TYPE[text]

class Verdict(Enum):
    ACCEPT = 1
    REJECT = 2
    VERBOSE_ACCEPT = 3

class TestInfo:
    def __init__(self):
        self.name = None
        self.insns = []
        self.map_fixups = {}
        self.result = None
        self.result_unpriv = None
        self.errstr = None
        self.errstr_unpriv = None
        self.retval = None
        self.flags = []
        self.sec = "socket" # default section
        self.imms = {}

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

def match_test_info(node):
    node.mtype('initializer_list')
    elems = iter(node.named_children)
    info = TestInfo()
    info.name = mnext(elems).mtype('string_literal').text
    while True:
        pair = next(elems, None)
        if pair is None:
            break
        pair.mtype('initializer_pair')
        field = pair['designator'][0].mtype('field_identifier').text
        value = pair['value']
        # print(f'  field={field} value={value}')
        match field:
            case 'insns':
                comments = []
                for insn in value.mtype('initializer_list').named_children:
                    if insn.type == 'comment':
                        comments.append(insn.text)
                    else:
                        text = convert_insn(insn)
                        text.comments = comments
                        info.insns.append(text)
                        comments = []
                if len(info.insns) > 0:
                    info.insns[-1].after_comments = comments
                else:
                    logging.warning(f'Dropping trailing comments {comments} at {value}')
            case 'errstr':
                info.errstr = value.text
            case 'errstr_unpriv':
                info.errstr_unpriv = value.text
            case 'result':
                info.result = parse_test_result(value, 'result')
            case 'result_unpriv':
                info.result_unpriv = parse_test_result(value, 'result_unpriv')
            case map_fixup if (map_name := map_fixup.removeprefix('fixup_')) in MAP_NAMES:
                info.map_fixups[map_name] = convert_int_list(value)
            case 'flags':
                info.flags.extend(convert_flags(value))
            case 'prog_type':
                info.sec = convert_prog_type(value)
            case 'retval':
                info.retval = value.text
            case _:
                logging.warning(f"Unsupported field '{field}' at {pair.start_point}:" +
                                f" {value.text}")
    return info

#################################
##### Instructions patching #####
#################################

def patch_ld_map_fd(text, map_name):
    if 'imm' in text.vars:
        text.vars['imm'] = Imm(f'&{map_name}')
    else:
        logging.warning(f'Unexpected insn to patch: {text}')
    return text

def insert_labels(insns):
    targets = {}
    counter = 0
    for i, insn in enumerate(insns):
        if isinstance(insn, str):
            print((i, insn))
        #print(f'{str(insn)}, {insn.template} {insn.vars}')
        if 'goto' not in insn.vars:
            continue
        target = i + insn.vars['goto'] + 1
        if target not in targets:
            targets[target] = f'l{counter}_%='
            counter += 1
        insn.vars['goto'] = targets[target]
    new_insns = []
    for i, insn in enumerate(insns):
        if i in targets:
            new_insns.append(DString(f'{targets[i]}:', {}))
        new_insns.append(insn)
    return new_insns

def guess_imm_basename(text):
    if m := re.match(r'^([\w\d]+)$', text):
        return m[1], False
    if m := re.match(r'^&([\w\d]+)$', text):
        return m[1], False
    if m := re.match(r'^offsetof\(struct ([\w\d]+), ([\w\d]+)\)$', text):
        return f'{m[1]}_{m[2]}_offset', False
    return '__imm', True

def gen_imm_name(text, counters):
    basename, force_counter = guess_imm_basename(text)
    counter = counters.get(basename, 0)
    counters[basename] = counter + 1
    if counter > 0 or force_counter:
        return f'{basename}_{counter}'
    else:
        return basename

def rename_imms(insns):
    text_to_name = {}
    counters = {}
    for insn in insns:
        for var_name, val in insn.vars.items():
            if not isinstance(val, Imm):
                continue
            if val.text not in text_to_name:
                text_to_name[val.text] = gen_imm_name(val.text, counters)
            imm_name = text_to_name[val.text]
            insn.vars[var_name] = f'%[{imm_name}]'
    return text_to_name

def format_imms(text_to_name):
    imms = []
    for text, name in text_to_name.items():
        if text == name:
            imms.append(f'__imm({name})')
        elif text == f'&{name}':
            imms.append(f'__imm_addr({name})')
        else:
            imms.append(f'[{name}]"i"({text})')
    imms.sort()
    return ",\n\t  ".join(imms)

def patch_test_info(info):
    for map_name in info.map_fixups.keys():
        for i in info.map_fixups[map_name]:
            info.insns[i] = patch_ld_map_fd(info.insns[i], map_name)
    info.imms = rename_imms(info.insns)
    info.insns = insert_labels(info.insns)

###############################
##### C code generation   #####
###############################

def enquote(text):
    # TODO: anything else to escape?
    escaped = text.replace('"', '\"')
    return f'"{escaped}"'

def format_comments(out, comments):
    # TODO: extend this with smarter newline handling one day
    for c in comments:
        out.write('\t')
        out.write(c)
        out.write('\n')

def format_insns(insns, newlines):
    with io.StringIO() as out:
        for i, insn in enumerate(insns):
            format_comments(out, getattr(insn, 'comments', []))
            text = str(insn)
            if not text.endswith(':'):
                out.write('\t')
            if newlines:
                out.write(enquote(f'{text}\\n'))
            else:
                out.write(enquote(text))
            out.write("\n")
            format_comments(out, getattr(insn, 'after_comments', []))
        return out.getvalue()

def cname_from_string(string):
    return re.sub(r'[^\d\w]', '_', string)

def collect_attrs(info, unpriv):
    attrs = []
    result = info.result
    errstr = info.errstr
    if unpriv:
        if info.result_unpriv:
            result = info.result_unpriv
        if info.errstr_unpriv:
            errstr = info.errstr_unpriv
    match result:
        case Verdict.VERBOSE_ACCEPT:
            attrs.append('__log_level(2)')
        case Verdict.REJECT:
            attrs.append('__failure')
    if errstr:
        attrs.append(f'__msg({errstr})')
    if info.retval:
        attrs.append(f'__retval({info.retval})')
    attrs.extend(info.flags)
    return attrs

def render_attrs(attrs):
    attrs = sorted(attrs, key=len)
    with io.StringIO() as out:
        line_len = 0
        for attr in attrs:
            if line_len + len(attr) > 80 and line_len != 0:
                out.write("\n")
                line_len = 0
            if line_len > 0:
                out.write(' ')
                line_len += 1
            out.write(attr)
            line_len += len(attr)
        if out.tell() != 0:
            out.write("\n")
        return out.getvalue()

def render_test_info(info, options):
    priv_attrs = collect_attrs(info, False)
    unpriv_attrs = collect_attrs(info, True)

    comment = info.name.strip('"')
    func_name = cname_from_string(comment)
    insn_text = format_insns(info.insns, options.newlines)
    imms_text = format_imms(info.imms)

    if priv_attrs == unpriv_attrs:
        priv_attrs.append('__naked')
        priv_attrs.append('__priv_and_unpriv')
        return f'''
/* {comment} */
SEC("{info.sec}")
{render_attrs(priv_attrs)}void {func_name}(void)
{{
	asm volatile (
{insn_text}	:
	: {imms_text}
	: __clobber_all);
}}
'''
    else:
        unpriv_attrs.append('__unpriv')
        return f'''
/* {comment} */
__naked __always_inline
void {func_name}_body(void)
{{
	asm volatile (
{insn_text}	:
	: {imms_text}
	: __clobber_all);
}}

SEC("{info.sec}")
{render_attrs(priv_attrs)}void {func_name}(void)
{{
	{func_name}_body();
}}

SEC("{info.sec}")
{render_attrs(unpriv_attrs)}void {func_name}_unpriv(void)
{{
	{func_name}_body();
}}
'''

MAP_NAMES = set(['map_hash_48b', 'map_hash_16b', 'map_hash_8b',
                 'cgroup_storage', 'percpu_cgroup_storage'])

def print_auxiliary_definitions(out, infos):
    used_maps = set()

    for info in infos:
        for map_name, fixups in info.map_fixups.items():
            if fixups:
                used_maps.add(map_name)

    def need_map(*names):
        return any([n in used_maps for n in names])

    def do_print(text):
        out.write(text)

    if need_map('map_hash_48b', 'map_hash_16b', 'map_hash_8b'):
        do_print('''
#define MAX_ENTRIES 11
''')

    if need_map('cgroup_storage', 'percpu_cgroup_storage'):
        do_print('''
#define TEST_DATA_LEN 64
''')

    if need_map('map_hash_48b'):
        do_print('''
struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct test_val);
} map_hash_48b SEC(".maps");
''')

    if need_map('map_hash_16b'):
            do_print('''
struct other_val {
	long long foo;
	long long bar;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct other_val);
} map_hash_16b SEC(".maps");
''')

    if need_map('map_hash_8b'):
        do_print('''
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, long long);
} map_hash_8b SEC(".maps");
''')

    if need_map('cgroup_storage'):
        do_print('''
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
	__uint(max_entries, 0);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, char[TEST_DATA_LEN]);
} cgroup_storage SEC(".maps");
''')

    if need_map('percpu_cgroup_storage'):
        do_print('''
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
	__uint(max_entries, 0);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, char[64]);
} cgroup_storage SEC(".maps");
''')

LICENSE = '''
// SPDX-License-Identifier: GPL-2.0
'''.lstrip()

INCLUDES = '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
'''.lstrip()

@dataclass
class Options:
    newlines: bool = False

@dataclass
class TopComment:
    text: str

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
            entries.append(TopComment(test_node.text))
        else:
            try:
                entries.append(TestCase(match_test_info(test_node)))
            except MatchError as error:
                short_text = test_node.text[0:40]
                logging.warning(f"""
Can't convert test case:
  Location: {test_node.start_point} '{short_text}...'
  Error   : {error}
""")

    with io.StringIO() as out:
        out.write(LICENSE)
        out.write("\n")
        out.write(INCLUDES)
        print_auxiliary_definitions(out, map(lambda e: e.info,
                                             filter(lambda e: isinstance(e, TestCase), entries)))
        for entry in entries:
            match entry:
                case TestCase(info):
                    patch_test_info(info)
                    out.write(render_test_info(info, options))
                case TopComment(text):
                    out.write(text)
                    out.write("\n")
        return out.getvalue()

###############################
#####    Entry points     #####
###############################

def convert_string(full_text, options):
    fake_input = 'struct foo x[] = {' + "\n" + full_text + "\n" + '};'
    parser = Parser()
    parser.set_language(C_LANGUAGE)
    tree = parser.parse(bytes(fake_input, encoding='utf8'))
    return convert_translation_unit(tree.root_node, options)

def convert_file(file_name, options):
    with open(file_name, 'r') as f:
        print(convert_string(f.read(), options))

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--debug', action=argparse.BooleanOptionalAction)
    p.add_argument('--newlines', action=argparse.BooleanOptionalAction)
    p.add_argument('file_name', type=str)
    args = p.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, force=True)
    convert_file(args.file_name, Options(newlines=args.newlines))

# TODO:
# - preserve comments
