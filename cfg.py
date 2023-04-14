import sys
import logging
from dstring import *
from functools import reduce
from dataclasses import dataclass, field

@dataclass
class BB:
    start: int
    insns: list = field(default_factory=list)
    exits: list = field(default_factory=list)

def build_cfg(insns):
    bbs = {}
    cur_bb = None

    def ensure_bb(idx):
        if idx < 0 or idx >= len(insns):
            return None
        if idx not in bbs:
            bbs[idx] = BB(idx)
        return idx

    def cur_bb_add_exit(idx):
        if idx:
            cur_bb.exits.append(idx)

    for i, insn in enumerate(insns):
        if goto := insn.vars.get('goto', None):
            ensure_bb(i + goto + 1)

    for i, insn in enumerate(insns):
        def target():
            return i + insn.vars['goto'] + 1

        if not cur_bb:
            ensure_bb(i)
            cur_bb = bbs[i]
        elif insn_bb := bbs.get(i, None):
            cur_bb_add_exit(i)
            cur_bb = insn_bb

        cur_bb.insns.append((i, insn))
        text = str(insn)
        if text.startswith('if'):
            cur_bb_add_exit(ensure_bb(target()))
            cur_bb_add_exit(ensure_bb(i + 1))
            cur_bb = None
        elif text.startswith('goto'):
            cur_bb_add_exit(ensure_bb(target()))
            cur_bb = None
        elif text.startswith('exit'):
            ensure_bb(i + 1)
            cur_bb = None

    return bbs

def post_order(bbs):
    visited = set()
    order = []

    def visit(i):
        if i in visited:
            return
        visited.add(i)
        for e in bbs[i].exits:
            visit(e)
        order.append(i)

    for i in sorted(bbs.keys()):
        visit(i)

    return order

CALL_MASK = reduce(lambda a, i: a | 1<<i, range(0, 6), 0)

def gen_kill(insn):
    def reg_mask(reg):
        if reg:
            return 1 << int(reg[1:])
        else:
            return 0

    text = str(insn)
    if text == 'exit;':
        return 1, 0

    if text.startswith('call') or getattr(insn, 'call_like', False):
        return CALL_MASK, CALL_MASK

    dst_action = insn.dst_action
    src = reg_mask(insn.vars.get('src', None))
    dst = reg_mask(insn.vars.get('dst', None))
    match dst_action:
        case 'r':
            gen  = src | dst
            kill = 0
        case 'w':
            gen  = src
            kill = dst
        case 'rw':
            gen  = src | dst
            kill = dst
        case None:
            gen  = src
            kill = 0
        case _:
            raise Exception('Unexpected dst_action: {dst_action}')
    return gen, kill

@dataclass
class InsnState:
    gen : int
    kill: int
    _in : int
    out : int

def compute_live_regs(insns):
    cfg = build_cfg(insns)
    bb_order = list(map(lambda i: cfg[i], post_order(cfg)))
    state = []
    for insn in insns:
        gen, kill = gen_kill(insn)
        state.append(InsnState(gen=gen, kill=kill, _in=0, out=0))
    changed = True
    while changed:
        changed = False
        for bb in bb_order:
            out = 0
            for e in bb.exits:
                ebb = cfg[e]
                idx, _ = ebb.insns[0]
                out |= state[idx]._in
            for i, _ in reversed(bb.insns):
                s = state[i]
                _in = s.gen | (out & ~s.kill)
                if s.out | out != s.out:
                    changed = True
                if s._in | _in != s._in:
                    changed = True
                s.out |= out
                s._in |= _in
                out = s._in
    live_regs = []
    for i in range(0, len(insns)):
        s = state[i]
        regs = []
        for r in range(0, 10):
            if (1 << r) & s._in:
                regs.append(r)
        live_regs.append(regs)
    return live_regs

def format_basic_block(bb, live_regs):
    max_width = 0
    insns_as_text = []
    for idx, insn in bb.insns:
        text = str(insn)
        insns_as_text.append((idx, text))
        max_width = max(max_width, len(text))
    formatted_insns = []
    for idx, insn in insns_as_text:
        if iregs := live_regs[idx]:
            regs = ' ; ' + ", ".join(map(str, iregs))
            fill_width = max_width
        else:
            regs = ''
            fill_width = 0
        formatted_insns.append(f'{idx:<2}: {insn.ljust(fill_width)}{regs}')
    return formatted_insns

def cfg_to_dot(out, bbs, live_regs):
    font='Monospace'
    out.write('digraph G {\n')
    out.write('  node [shape=box];\n')
    out.write(f"  graph [fontname=\"{font}\"];\n")
    out.write(f"  node  [fontname=\"{font}\"];\n")
    out.write(f"  edge  [fontname=\"{font}\"];\n")
    for i, bb in sorted(bbs.items(), key=lambda p: p[0]):
        bb_text = '\\l\\\n'.join(format_basic_block(bb, live_regs))
        out.write(f'  {i} [label="\\\n{bb_text}"];\n')
        if bb.exits:
            exits_text = " ".join(map(str, sorted(bb.exits)))
            out.write(f'  {i} -> {{ {exits_text} }};\n')
    out.write('}\n')

def cfg_to_text(out, bbs, live_regs):
    for i, bb in sorted(bbs.items(), key=lambda p: p[0]):
        bb_text = '\n  '.join(format_basic_block(bb, live_regs))
        out.write(f'# {bb_text}\n')
        if bb.exits:
            exits_text = " ".join(map(str, sorted(bb.exits)))
            out.write(f' -> {exits_text}\n')
