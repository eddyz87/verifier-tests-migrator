#!/usr/bin/python3

import re
import io
import sys
import rewrite
import logging
import unittest
import subprocess
from tree_sitter_matching import *
from cfg import build_cfg, compute_live_regs, cfg_to_dot, cfg_to_text
from rewrite import convert_string, Options, convert_insn_list, parse_c_string

class Tests(unittest.TestCase):
    def _aux(self, input, expected_output, options=Options()):
        output = convert_string(input, options)
        self.maxDiff = None
        self.assertMultiLineEqual(expected_output.lstrip(), output,)

    def test_simple(self):
        self._aux('''
{
	/* some
	 * comment
	 */
	"invalid and of negative number",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8 + 2),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_1, -4),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
	BPF_ALU64_IMM(BPF_MOD, BPF_REG_1, 2),
	BPF_ALU64_IMM(BPF_OR, BPF_REG_1, 2),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
	BPF_ALU64_REG(BPF_NEG, BPF_REG_1, BPF_REG_1),
	BPF_ALU32_REG(BPF_NEG, BPF_REG_1, BPF_REG_1),
	BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, 0),
	BPF_ALU32_IMM(BPF_NEG, BPF_REG_2, 0),
	// invalid LD_MAP_FD (it is not patched)
	BPF_LD_MAP_FD(BPF_REG_7, 32),
	BPF_LD_MAP_FD(BPF_REG_8, 42),
	// comment
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val,
						  foo)),
	BPF_CALL_REL(1),
	BPF_EXIT_INSN(),
	//
	BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 16),
	BPF_ENDIAN(BPF_TO_LE, BPF_REG_1, 32),
	BPF_ENDIAN(BPF_TO_LE, BPF_REG_2, 64),
	//
	BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 16),
	BPF_ENDIAN(BPF_TO_BE, BPF_REG_1, 32),
	BPF_ENDIAN(BPF_TO_BE, BPF_REG_2, 64),
	//
	BPF_ENDIAN(BPF_FROM_LE, BPF_REG_0, 16),
	BPF_ENDIAN(BPF_FROM_LE, BPF_REG_1, 32),
	BPF_ENDIAN(BPF_FROM_LE, BPF_REG_2, 64),
	//
	BPF_ENDIAN(BPF_FROM_BE, BPF_REG_0, 16),
	BPF_ENDIAN(BPF_FROM_BE, BPF_REG_1, 32),
	BPF_ENDIAN(BPF_FROM_BE, BPF_REG_2, 64),
	//
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr = "R0 max value is outside of the allowed memory range",
	.errstr_unpriv = "abra-cadabra",
	.result = REJECT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define MAX_ENTRIES 11

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

/* some
 * comment
 */
SEC("socket")
__description("invalid and of negative number")
__failure __msg("R0 max value is outside of the allowed memory range")
__msg_unpriv("abra-cadabra")
__flag(BPF_F_ANY_ALIGNMENT)
__naked void invalid_and_of_negative_number(void)
{
	asm volatile ("					\\
	*(u64*)(r10 - 8) = 0;				\\
	r2 = r10;					\\
	r2 += %[__imm_0];				\\
	r1 = %[map_hash_48b] ll;			\\
	call %[bpf_map_lookup_elem];			\\
	if r0 == 0 goto l0_%=;				\\
	r1 = *(u8*)(r0 + 0);				\\
l0_%=:	r1 &= -4;					\\
	r1 <<= 2;					\\
	r1 %%= 2;					\\
	r1 |= 2;					\\
	r0 += r1;					\\
	r1 = -r1;					\\
	w1 = -w1;					\\
	r2 = -r2;					\\
	w2 = -w2;					\\
	/* invalid LD_MAP_FD (it is not patched) */	\\
	.8byte %[ld_map_fd];				\\
	.8byte 0;					\\
	.8byte %[ld_map_fd_1];				\\
	.8byte 0;					\\
	/* comment */					\\
	*(u64*)(r0 + 0) = %[test_val_foo];		\\
	call invalid_and_of_negative_number__1;		\\
	exit;						\\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b),
	  __imm_const(__imm_0, -8 + 2),
	  __imm_const(test_val_foo, offsetof(struct test_val, foo)),
	  __imm_insn(ld_map_fd, BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_7, BPF_PSEUDO_MAP_FD, 0, 32)),
	  __imm_insn(ld_map_fd_1, BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_8, BPF_PSEUDO_MAP_FD, 0, 42))
	: __clobber_all);
}

static __naked __noinline __attribute__((used))
void invalid_and_of_negative_number__1(void)
{
	asm volatile ("					\\
	/* */						\\
	r0 = le16 r0;					\\
	r1 = le32 r1;					\\
	r2 = le64 r2;					\\
	/* */						\\
	r0 = be16 r0;					\\
	r1 = be32 r1;					\\
	r2 = be64 r2;					\\
	/* */						\\
	r0 = le16 r0;					\\
	r1 = le32 r1;					\\
	r2 = le64 r2;					\\
	/* */						\\
	r0 = be16 r0;					\\
	r1 = be32 r1;					\\
	r2 = be64 r2;					\\
	/* */						\\
	exit;						\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_double_size_insn(self):
        self._aux('''
{
	"dsize",
	.insns = {
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 0, 3, 6 },
	.result = ACCEPT,
},
''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, long long);
} map_hash_8b SEC(".maps");

SEC("socket")
__description("dsize")
__success __success_unpriv __retval(0)
__naked void dsize(void)
{
	asm volatile ("					\\
	r1 = %[map_hash_8b] ll;				\\
	exit;						\\
	r1 = %[map_hash_8b] ll;				\\
	exit;						\\
	r1 = %[map_hash_8b] ll;				\\
	exit;						\\
"	:
	: __imm_addr(map_hash_8b)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_double_size_insn2(self):
        self._aux('''
{
	"dsize2",
	.insns = {
	BPF_LD_IMM64(BPF_REG_1, 0),
	BPF_JMP_A(-3),
	BPF_LD_IMM64(BPF_REG_1, 0),
	BPF_JMP_A(-6),
	},
	.result = ACCEPT,
},
''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("dsize2")
__success __success_unpriv __retval(0)
__naked void dsize2(void)
{
	asm volatile ("					\\
l0_%=:	r1 = 0 ll;					\\
	goto l0_%=;					\\
	r1 = 0 ll;					\\
	goto l0_%=;					\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_long_label(self):
        self._aux('''
{
	"dsize2",
	.insns = {
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_JMP_A(-1),
	},
	.result = ACCEPT,
},
''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("dsize2")
__success __success_unpriv __retval(0)
__naked void dsize2(void)
{
	asm volatile ("					\\
	r0 = r0;					\\
l100_%=:						\\
	goto l100_%=;					\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''', options=Options(label_start=100))

    def test_atomic(self):
        self._aux('''
{
	"atomic",
	.insns = {
	BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH, BPF_REG_10, BPF_REG_1, -8),
	BPF_ATOMIC_OP(BPF_DW, BPF_AND | BPF_FETCH, BPF_REG_10, BPF_REG_2, -8),
	//
	BPF_ATOMIC_OP(BPF_W, BPF_FETCH | BPF_OR , BPF_REG_10, BPF_REG_3, -8),
	BPF_ATOMIC_OP(BPF_W, BPF_FETCH | BPF_XOR, BPF_REG_10, BPF_REG_4, -8),
	//
	BPF_ATOMIC_OP(BPF_W, BPF_ADD, BPF_REG_10, BPF_REG_1, -16),
	BPF_ATOMIC_OP(BPF_W, BPF_AND, BPF_REG_10, BPF_REG_2, -16),
	//
	BPF_ATOMIC_OP(BPF_DW, BPF_OR , BPF_REG_10, BPF_REG_3, -16),
	BPF_ATOMIC_OP(BPF_DW, BPF_XOR, BPF_REG_10, BPF_REG_4, -16),
	//
	BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_10, BPF_REG_1, -8),
	BPF_ATOMIC_OP(BPF_W, BPF_XCHG, BPF_REG_10, BPF_REG_1, -4),
	//
	BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
	BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -4),
        //
        BPF_RAW_INSN(BPF_STX | BPF_ATOMIC | BPF_DW, BPF_REG_10, BPF_REG_0, -8, BPF_ADD),
	},
	.result = ACCEPT,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("atomic")
__success __success_unpriv __retval(0)
__naked void atomic(void)
{
	asm volatile ("					\\
	r1 = atomic_fetch_add((u64 *)(r10 - 8), r1);	\\
	r2 = atomic_fetch_and((u64 *)(r10 - 8), r2);	\\
	/* */						\\
	w3 = atomic_fetch_or((u32 *)(r10 - 8), w3);	\\
	w4 = atomic_fetch_xor((u32 *)(r10 - 8), w4);	\\
	/* */						\\
	lock *(u32 *)(r10 - 16) += w1;			\\
	lock *(u32 *)(r10 - 16) &= w2;			\\
	/* */						\\
	lock *(u64 *)(r10 - 16) |= r3;			\\
	lock *(u64 *)(r10 - 16) ^= r4;			\\
	/* */						\\
	r1 = xchg_64(r10 - 8, r1);			\\
	w1 = xchg32_32(w10 - 4, w1);			\\
	/* */						\\
	r0 = cmpxchg_64(r10 - 8, r0, r1);		\\
	w0 = cmpxchg32_32(r10 - 4, w0, w1);		\\
	/* */						\\
	lock *(u64 *)(r10 - 8) += r0;			\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_comments(self):
        self._aux('''
{
	/* 1a */ /* 2a */
	/* 3a */
	"atomic",
	/* 1b */ /* 2b */
	/* 3b */
	.insns = {
	/* 1c */ /* 2c */
	/* 3c
         * 4c
         */
	BPF_ST_MEM(BPF_DW, BPF_REG_1, -16, 77),
	/* 1d */ /* 2d */
	/* 3d */
	},
	/* 1e */ /* 2e */
	/* 3e */
	.result = REJECT,
	/* 1f */ /* 2f */
	/* 3f */
	.result_unpriv = REJECT,
	/* 1g */ /* 2g */
	/* 3g */
	.errstr = 'foo',
	/* 1h */ /* 2h */
	/* 3h */
	.errstr_unpriv = 'bar',
	/* 1i */ /* 2i */
	/* 3i */
	.retval = 1,
	/* 1j */ /* 2j */
	/* 3j */
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* 1a */ /* 2a */
/* 3a */
SEC("socket")
__description("atomic")
/* 1e */ /* 2e */
/* 3e */
__failure
/* 1g */ /* 2g */
/* 3g */
__msg("foo")
/* 1f */ /* 2f */
/* 3f */
__failure_unpriv
/* 1h */ /* 2h */
/* 3h */
__msg_unpriv("bar")
/* 1i */ /* 2i */
/* 3i */
__retval(1)
/* 1j */ /* 2j */
/* 3j */
__flag(BPF_F_ANY_ALIGNMENT)
__naked void atomic(void)
{
	/* 1b */ /* 2b */
	/* 3b */
	asm volatile ("					\\
	/* 1c */ /* 2c */				\\
	/* 3c						\\
	 * 4c						\\
	 */						\\
	r0 = 77;					\\
	*(u64*)(r1 - 16) = r0;				\\
	/* 1d */ /* 2d */				\\
	/* 3d */					\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''', Options(replace_st_mem=True))

    def test_rewrap_comments(self):
        self._aux('''
{
	"atomic",
	.insns = {
	/* a */
	// b
	// c
	/* d */
	BPF_ST_MEM(BPF_DW, BPF_REG_1, -16, 77),
	// a
	// b
	/* c */
	},
        .result = ACCEPT,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("atomic")
__success __success_unpriv __retval(0)
__naked void atomic(void)
{
	asm volatile ("					\\
	/* a */						\\
	/* b						\\
	 * c						\\
	 */						\\
	/* d */						\\
	*(u64*)(r1 - 16) = 77;				\\
	/* a						\\
	 * b						\\
	 */						\\
	/* c */						\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_dummy_comments_removal(self):
        self._aux('''
{
	"comments test",
	.insns = {
	/* r1 = 42 */
	BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 42),
	/* w1 = 42; */
	BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 42),
	/* r1   = 42, */
	BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 42),
	/* r1 = 142 */
	BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 42),
	},
	.result = ACCEPT
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("comments test")
__success __success_unpriv __retval(0)
__naked void comments_test(void)
{
	asm volatile ("					\\
	r1 = 42;					\\
	r1 = 42;					\\
	r1 = 42;					\\
	/* r1 = 142 */					\\
	r1 = 42;					\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_off(self):
        self._aux('''
{
	"imm",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, offsetof(struct foo, bar)),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -offsetof(struct foo, bar)),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, offsetof(struct foo, buz[7])),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 42),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -7),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, -foo, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_OR , BPF_REG_10, BPF_REG_3, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_10, BPF_REG_1, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -foo),
	BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, sizeof(struct foo)),
	},
	.result = REJECT,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("imm")
__failure __failure_unpriv
__naked void imm(void)
{
	asm volatile ("					\\
	r0 = *(u64*)(r1 + %[foo_bar]);			\\
	r0 = *(u64*)(r1 - %[foo_bar]);			\\
	r0 = *(u64*)(r1 + %[foo_buz_7]);		\\
	r0 = *(u64*)(r1 + 42);				\\
	r0 = *(u64*)(r1 - 7);				\\
	*(u64*)(r0 - %[foo]) = -8;			\\
	*(u64*)(r0 - %[foo]) = r1;			\\
	lock *(u64 *)(r10 - %[foo]) |= r3;		\\
	r1 = xchg_64(r10 - %[foo], r1);			\\
	r0 = cmpxchg_64(r10 - %[foo], r0, r1);		\\
	r0 = %[sizeof_foo];				\\
"	:
	: __imm(foo),
	  __imm_const(foo_bar, offsetof(struct foo, bar)),
	  __imm_const(foo_buz_7, offsetof(struct foo, buz[7])),
	  __imm_const(sizeof_foo, sizeof(struct foo))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_result_attrs(self):
        self._aux('''
{ "t1", },
{ "t2", .result = ACCEPT, },
{ "t2.1", .result = ACCEPT, .runs = -1 },
{ "t3", .result = VERBOSE_ACCEPT, },
{ "t4", .result = REJECT, },
{ "t5", .result = ACCEPT, .errstr = "x" },
{ "t6", .result = ACCEPT, .errstr = "x", .result_unpriv = REJECT, .errstr_unpriv = "y" },
{ "t7", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_SOCKET_FILTER },
{ "t8", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_CGROUP_SKB },
{ "t9", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_LSM },
{ "t10", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_LSM,
         .errstr = "foo\\
	bar" },
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("t1")
__failure __failure_unpriv
__naked void t1(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t2")
__success __success_unpriv __retval(0)
__naked void t2(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t2.1")
__success __success_unpriv
__naked void t2_1(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t3")
__success __success_unpriv __log_level(2) __retval(0)
__naked void t3(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t4")
__failure __failure_unpriv
__naked void t4(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t5")
__success __msg("x")
__success_unpriv
__retval(0)
__naked void t5(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t6")
__success __msg("x")
__failure_unpriv __msg_unpriv("y")
__retval(0)
__naked void t6(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("socket")
__description("t7")
__success __success_unpriv __retval(0)
__naked void t7(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("cgroup/skb")
__description("t8")
__success __success_unpriv __retval(0)
__naked void t8(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("lsm")
__description("t9")
__success
__naked void t9(void)
{
	asm volatile ("" ::: __clobber_all);
}

SEC("lsm")
__description("t10")
__success
__msg("foo")
__msg("bar")
__naked void t10(void)
{
	asm volatile ("" ::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_bad_insns(self):
        self._aux('''
{
	"imm",
	.insns = {
	BPF_ALU64_IMM(12),
	BPF_ALU64_REG(CAPIBARA, BPF_REG_1, BPF_REG_2),
	BPF_LD_IMM64(),
	},
	.result = ACCEPT,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

SEC("socket")
__description("imm")
__success __success_unpriv __retval(0)
__naked void imm(void)
{
	asm volatile ("					\\
	.8byte %[alu64_imm];				\\
	.8byte %[alu64_reg];				\\
	NOT CONVERTED: BPF_LD_IMM64()			\\
"	:
	: __imm_insn(alu64_imm, BPF_ALU64_IMM(12)),
	  __imm_insn(alu64_reg, BPF_ALU64_REG(CAPIBARA, BPF_REG_1, BPF_REG_2))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_kfunc(self):
        self._aux('''
{
	"kfunc",
	.insns = {
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.fixup_kfunc_btf_id = {
		{ "bpf_kfunc_call_test_acquire", 0 },
		{ "bpf_kfunc_call_test_release", 1 },
	},
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct prog_test_ref_kfunc {} __attribute__((preserve_access_index));

extern struct prog_test_ref_kfunc *
	bpf_kfunc_call_test_acquire(unsigned long *scalar_ptr) __ksym;
extern void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p) __ksym;

/* BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root()
{
	bpf_kfunc_call_test_acquire(0);
	bpf_kfunc_call_test_release(0);
}

SEC("socket")
__description("kfunc")
__success __success_unpriv __retval(0)
__naked void kfunc(void)
{
	asm volatile ("					\\
	call %[bpf_kfunc_call_test_acquire];		\\
	call %[bpf_kfunc_call_test_release];		\\
	exit;						\\
"	:
	: __imm(bpf_kfunc_call_test_acquire),
	  __imm(bpf_kfunc_call_test_release)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_macro1(self):
        self._aux('''
{
	"macro",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
		    offsetofend(struct __sk_buff, gso_size)),
	},
	.result = ACCEPT,
},
''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \\
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))

SEC("socket")
__description("macro")
__success __success_unpriv __retval(0)
__naked void macro(void)
{
	asm volatile ("					\\
	r0 = *(u32*)(r1 + %[__sk_buff_gso_size__end]);	\\
"	:
	: __imm_const(__sk_buff_gso_size__end, offsetofend(struct __sk_buff, gso_size))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_string_per_insn(self):
        self._aux('''
{
	"string_per_insn",
	.insns = {
	/* Comment line #1
	 * Comment line #2
         */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	/* Another comment */
	BPF_EXIT_INSN()
	},
	.result = ACCEPT
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("string_per_insn")
__success __success_unpriv __retval(0)
__naked void string_per_insn(void)
{
	asm volatile (
	/* Comment line #1
	 * Comment line #2
	 */
	"r0 = 0;"
	/* Another comment */
	"exit;"
	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''', Options(string_per_insn=True))

    def test_pseudocall1(self):
        self._aux('''
{
	"pseudocall",
	.insns = {
        /* c1 */
	BPF_CALL_REL(1),
        /* c2 */
	BPF_EXIT_INSN(),
	/* c3 */
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, -3),
	/* c4 */
	},
	.result = ACCEPT
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("pseudocall")
__success __success_unpriv __retval(0)
__naked void pseudocall(void)
{
	asm volatile ("					\\
	/* c1 */					\\
	call pseudocall__1;				\\
	/* c2 */					\\
	exit;						\\
"	::: __clobber_all);
}

static __naked __noinline __attribute__((used))
void pseudocall__1(void)
{
	asm volatile ("					\\
	/* c3 */					\\
	call pseudocall;				\\
	/* c4 */					\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_pseudocall2(self):
        self._aux('''
{
	"pseudocall",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, bar),
	BPF_CALL_REL(1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, foo),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("pseudocall")
__success __success_unpriv __retval(0)
__naked void pseudocall(void)
{
	asm volatile ("					\\
	r0 = %[bar];					\\
	call pseudocall__1;				\\
	exit;						\\
"	:
	: __imm(bar)
	: __clobber_all);
}

static __naked __noinline __attribute__((used))
void pseudocall__1(void)
{
	asm volatile ("					\\
	r0 = %[foo];					\\
	exit;						\\
"	:
	: __imm(foo)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_prog_with_attach_type_1(self):
        self._aux('''
{
	"pseudocall",
	.insns = {},
        .prog_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        .expected_attach_type = BPF_CGROUP_INET4_CONNECT,
	.result = ACCEPT
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("cgroup/connect4")
__description("pseudocall")
__success
__naked void pseudocall(void)
{
	asm volatile ("" ::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''',
                Options(string_per_insn=True))

    def test_prog_with_attach_type_2(self):
        self._aux('''
{
	"pseudocall",
	.insns = {},
        .prog_type = BPF_PROG_TYPE_LSM,
        .expected_attach_type = BPF_LSM_MAC,
        .kfunc = "barumba",
	.result = ACCEPT
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("lsm/barumba")
__description("pseudocall")
__success
__naked void pseudocall(void)
{
	asm volatile ("" ::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''',
                Options(string_per_insn=True))

    def test_prog_with_attach_type_3(self):
        self._aux('''
{
	"pseudocall",
	.insns = {},
        .prog_type = BPF_PROG_TYPE_LSM,
        .expected_attach_type = BPF_LSM_MAC,
        .kfunc = "barumba",
        .flags = BPF_F_SLEEPABLE,
	.result = ACCEPT
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("lsm.s/barumba")
__description("pseudocall")
__success
__naked void pseudocall(void)
{
	asm volatile ("" ::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''',
                Options(string_per_insn=True))

    def test_bpf_sk_lookup(self):
        self._aux('''
{
	"foobar",
	.insns = {
            BPF_SK_LOOKUP(skc_lookup_tcp),
            BPF_JMP_A(-14),
	},
	.result = ACCEPT,
},
{
	"buz",
	.insns = {
            BPF_SK_LOOKUP(skc_lookup_tcp),
	    BPF_EXIT_INSN(),
            BPF_SK_LOOKUP(skc_lookup_tcp),
	    BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

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

SEC("socket")
__description("foobar")
__success __success_unpriv __retval(0)
__naked void foobar(void)
{
	asm volatile ("					\\
l0_%=:"	BPF_SK_LOOKUP(bpf_skc_lookup_tcp)
"	goto l0_%=;					\\
"	:
	: __imm(bpf_skc_lookup_tcp),
	  __imm_const(sizeof_bpf_sock_tuple, sizeof(struct bpf_sock_tuple))
	: __clobber_all);
}

SEC("socket")
__description("buz")
__success __success_unpriv __retval(0)
__naked void buz(void)
{
	asm volatile (
	BPF_SK_LOOKUP(bpf_skc_lookup_tcp)
"	exit;						\\
"	BPF_SK_LOOKUP(bpf_skc_lookup_tcp)
"	exit;						\\
"	:
	: __imm(bpf_skc_lookup_tcp),
	  __imm_const(sizeof_bpf_sock_tuple, sizeof(struct bpf_sock_tuple))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_bpf_sk_lookup_string_per_insn(self):
        self._aux('''
{
	"buz",
	.insns = {
            BPF_SK_LOOKUP(skc_lookup_tcp),
	    BPF_EXIT_INSN(),
            BPF_SK_LOOKUP(skc_lookup_tcp),
	    BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

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

SEC("socket")
__description("buz")
__success __success_unpriv __retval(0)
__naked void buz(void)
{
	asm volatile (
	BPF_SK_LOOKUP(bpf_skc_lookup_tcp)
	"exit;"
	BPF_SK_LOOKUP(bpf_skc_lookup_tcp)
	"exit;"
	:
	: __imm(bpf_skc_lookup_tcp),
	  __imm_const(sizeof_bpf_sock_tuple, sizeof(struct bpf_sock_tuple))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''',
                  Options(string_per_insn=True))

    def test_prog_maps(self):
        self._aux('''
{
	"birim-burum",
	.insns = {
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_1),
	BPF_MOV64_IMM(BPF_REG_3, 3),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),

	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
	BPF_MOV64_IMM(BPF_REG_3, 3),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),
	},
	.fixup_prog1 = { 2 },
	.fixup_prog2 = { 7 },
	.result = ACCEPT,
},
        ''', '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

void dummy_prog_42_socket(void);
void dummy_prog_24_socket(void);
void dummy_prog_loop1_socket(void);
void dummy_prog_loop2_socket(void);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__uint(key_size, sizeof(int));
	__array(values, void (void));
} map_prog1_socket SEC(".maps") = {
	.values = {
		[0] = (void *) &dummy_prog_42_socket,
		[1] = (void *) &dummy_prog_loop1_socket,
		[2] = (void *) &dummy_prog_24_socket,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 8);
	__uint(key_size, sizeof(int));
	__array(values, void (void));
} map_prog2_socket SEC(".maps") = {
	.values = {
		[1] = (void *) &dummy_prog_loop2_socket,
		[2] = (void *) &dummy_prog_24_socket,
		[7] = (void *) &dummy_prog_42_socket,
	},
};

SEC("socket")
__auxiliary __auxiliary_unpriv
__naked void dummy_prog_42_socket(void) {
	asm volatile ("r0 = 42; exit;");
}

SEC("socket")
__auxiliary __auxiliary_unpriv
__naked void dummy_prog_24_socket(void) {
	asm volatile ("r0 = 24; exit;");
}

SEC("socket")
__auxiliary __auxiliary_unpriv
__naked void dummy_prog_loop1_socket(void) {
	asm volatile ("			\\
	r3 = 1;				\\
	r2 = %[map_prog1_socket] ll;	\\
	call %[bpf_tail_call];		\\
	r0 = 41;			\\
	exit;				\\
"	:
	: __imm(bpf_tail_call),
	  __imm_addr(map_prog1_socket)
	: __clobber_all);
}

SEC("socket")
__auxiliary __auxiliary_unpriv
__naked void dummy_prog_loop2_socket(void) {
	asm volatile ("			\\
	r3 = 1;				\\
	r2 = %[map_prog2_socket] ll;	\\
	call %[bpf_tail_call];		\\
	r0 = 41;			\\
	exit;				\\
"	:
	: __imm(bpf_tail_call),
	  __imm_addr(map_prog2_socket)
	: __clobber_all);
}

SEC("socket")
__description("birim-burum")
__success __success_unpriv __retval(0)
__naked void birim_burum(void)
{
	asm volatile ("					\\
	r7 = r1;					\\
	r3 = 3;						\\
	r2 = %[map_prog1_socket] ll;			\\
	call %[bpf_tail_call];				\\
	r1 = r7;					\\
	r3 = 3;						\\
	r2 = %[map_prog2_socket] ll;			\\
	call %[bpf_tail_call];				\\
"	:
	: __imm(bpf_tail_call),
	  __imm_addr(map_prog1_socket),
	  __imm_addr(map_prog2_socket)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_state_freq_flag(self):
        self._aux('''
{
	"foobar",
	.insns = { BPF_EXIT_INSN() },
	.result = ACCEPT,
        .flags = BPF_F_TEST_STATE_FREQ
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("foobar")
__success __success_unpriv __retval(0) __flag(BPF_F_TEST_STATE_FREQ)
__naked void foobar(void)
{
	asm volatile ("					\\
	exit;						\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

    def test_insn_processed(self):
        self._aux('''
{
	"foobar",
	.insns = { BPF_EXIT_INSN() },
        /* comment */
        .insn_processed = 42,
	.result = ACCEPT,
},
''',
                  '''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("foobar")
__success
/* comment */
__msg("processed 42 insns")
__success_unpriv __msg_unpriv("") __log_level(1) __retval(0)
__naked void foobar(void)
{
	asm volatile ("					\\
	exit;						\\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";''')

def insns_from_string(text):
    root = NodeWrapper(parse_c_string(f'''
long x[] = {{
{text}
}}
'''))
    insns_list = root[0][1][1]
    return convert_insn_list(insns_list.named_children, {}, {})

def show_cfg(text):
    insns = insns_from_string(text)
    cfg = build_cfg(insns)
    live_regs = compute_live_regs(insns)
    with io.StringIO() as out:
        cfg_to_dot(out, cfg, live_regs)
        dot = out.getvalue()
    cfg_to_text(sys.stdout, cfg, live_regs)
    proc = subprocess.Popen(['bash', '-c', 'dot -Tpng | feh -'], stdin=subprocess.PIPE)
    proc.communicate(bytes(dot, encoding='utf8'))

class LiveRegTests(unittest.TestCase):
    def _aux(self, input, expected_output):
        insns = insns_from_string(input)
        cfg = build_cfg(insns)
        live_regs = compute_live_regs(insns)
        #live_regs = [[]]*100
        with io.StringIO() as out:
            cfg_to_text(out, cfg, live_regs)
            output = out.getvalue()
        self.maxDiff = None
        self.assertMultiLineEqual(expected_output.strip(), output.strip(),)

    def test_exit_r0(self):
        self._aux('''
	BPF_EXIT_INSN()
''', '''
# 0 : exit; ; 0
''')

    def test_branch1(self):
        self._aux('''
BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 1),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 2),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_3, 0, 2),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
BPF_EXIT_INSN(),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_2),
BPF_EXIT_INSN(),
''', '''
# 0 : r1 = 1;            ; 3
  1 : r2 = 2;            ; 1, 3
  2 : if r3 == 0 goto 2; ; 1, 2, 3
 -> 3 5
# 3 : r0 = r1; ; 1
  4 : exit;    ; 0
# 5 : r0 = r2; ; 2
  6 : exit;    ; 0
''')

    def test_same_label1(self):
        self._aux('''
BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 1),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 2),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_3, 0, 3),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_3, 1, 2),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
BPF_EXIT_INSN(),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_2),
BPF_EXIT_INSN(),
''', '''
# 0 : r1 = 1;            ; 3
  1 : r2 = 2;            ; 1, 3
  2 : if r3 == 0 goto 3; ; 1, 2, 3
 -> 3 6
# 3 : if r3 == 1 goto 2; ; 1, 2, 3
 -> 4 6
# 4 : r0 = r1; ; 1
  5 : exit;    ; 0
# 6 : r0 = r2; ; 2
  7 : exit;    ; 0
''')

    def test_loop1(self):
        self._aux('''
BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 10),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 0),
BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1),
BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),
BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, -3),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
BPF_EXIT_INSN(),
''', '''
# 0 : r1 = 10;
  1 : r2 = 0;  ; 1
 -> 2
# 2 : r2 += r1;           ; 1, 2
  3 : r1 -= 1;            ; 1, 2
  4 : if r1 != 0 goto -3; ; 1, 2
 -> 2 5
# 5 : r0 = r1; ; 1
  6 : exit;    ; 0
''')

    def test_call1(self):
        self._aux('''
BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 1),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 2),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_3, 3),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_4, 4),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_5, 5),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_6, 6),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_7, 7),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_8, 8),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 9),
BPF_CALL_REL(6),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_6),
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_8),
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_9),
BPF_EXIT_INSN(),
// called
BPF_EXIT_INSN(),
''', '''
# 0 : r0 = 0;
  1 : r1 = 1;   ; 0
  2 : r2 = 2;   ; 0, 1
  3 : r3 = 3;   ; 0, 1, 2
  4 : r4 = 4;   ; 0, 1, 2, 3
  5 : r5 = 5;   ; 0, 1, 2, 3, 4
  6 : r6 = 6;   ; 0, 1, 2, 3, 4, 5
  7 : r7 = 7;   ; 0, 1, 2, 3, 4, 5, 6
  8 : r8 = 8;   ; 0, 1, 2, 3, 4, 5, 6, 7
  9 : r9 = 9;   ; 0, 1, 2, 3, 4, 5, 6, 7, 8
  10: call 6;   ; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
  11: r0 = 0;   ; 6, 7, 8, 9
  12: r0 += r6; ; 0, 6, 7, 8, 9
  13: r0 += r7; ; 0, 7, 8, 9
  14: r0 += r8; ; 0, 8, 9
  15: r0 += r9; ; 0, 9
  16: exit;     ; 0
# 17: exit; ; 0
''')

    def test_call2(self):
        self._aux('''
BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
''', '''
# 0 : call Imm(text='bpf_map_lookup_elem', base_name=None, insn=False); ; 0, 1, 2, 3, 4, 5
''')

    def test_call_r0(self):
        self._aux('''
BPF_ALU64_IMM(BPF_MOV, BPF_REG_6, 42),
BPF_CALL_REL(3),
BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_0),
BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_6),
BPF_EXIT_INSN(),
// called
BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 1),
BPF_EXIT_INSN(),
''', '''
# 0 : r6 = 42;  ; 0, 1, 2, 3, 4, 5
  1 : call 3;   ; 0, 1, 2, 3, 4, 5, 6
  2 : r6 += r0; ; 0, 6
  3 : r0 = r6;  ; 6
  4 : exit;     ; 0
# 5 : r0 = 0;
  6 : r1 = 1; ; 0
  7 : exit;   ; 0
''')

    def test_ldx_stx1(self):
        self._aux('''
BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_3, -8),
BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_4, -8),
BPF_EXIT_INSN(),
''', '''
# 0 : r1 = *(u64*)(r3 - 8); ; 0, 2, 3, 4
  1 : *(u64*)(r2 - 8) = r4; ; 0, 2, 4
  2 : exit;                 ; 0
''')

class ReplaceSTMem(unittest.TestCase):
    def _aux_st(self, input, expected_output):
        insns = insns_from_string(input)
        insns = rewrite.replace_st_mem(insns)
        insns = rewrite.insert_labels(insns, Options())
        with io.StringIO() as out:
            for insn in insns:
                text = str(insn)
                if not text.endswith(':'):
                    out.write('\t')
                out.write(text)
                out.write('\n')
            output = out.getvalue()
        self.maxDiff = None
        self.assertMultiLineEqual(expected_output.strip(), output.strip())

    def test_simple(self):
        self._aux_st('''
BPF_ST_MEM(BPF_DW, BPF_REG_9, -8, 42),
BPF_EXIT_INSN(),
''', '''
	r1 = 42;
	*(u64*)(r9 - 8) = r1;
	exit;
''')

    def test_adjust_goto(self):
        self._aux_st('''
BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 7, 1),
BPF_ST_MEM(BPF_DW, BPF_REG_9, -8, 42),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 17, 2),
BPF_ST_MEM(BPF_DW, BPF_REG_9, -8, 72),
BPF_ST_MEM(BPF_DW, BPF_REG_1, -16, 77),
BPF_EXIT_INSN(),
''', '''
	if r0 == 7 goto l0_%=;
	r2 = 42;
	*(u64*)(r9 - 8) = r2;
l0_%=:
	if r0 == 17 goto l1_%=;
	r2 = 72;
	*(u64*)(r9 - 8) = r2;
	r2 = 77;
	*(u64*)(r1 - 16) = r2;
l1_%=:
	exit;
''')

    def test_goto_out_of_bounds(self):
        self._aux_st('''
BPF_ST_MEM(BPF_DW, BPF_REG_9, -8, 42),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 17, -3),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 14, 4),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 12, 4),
BPF_ST_MEM(BPF_DW, BPF_REG_9, -8, 72),
BPF_ST_MEM(BPF_DW, BPF_REG_1, -16, 77),
BPF_EXIT_INSN(),
''', '''
	r2 = 42;
	*(u64*)(r9 - 8) = r2;
	if r0 == 17 goto -4;
	if r0 == 14 goto l0_%=;
	if r0 == 12 goto 6;
	r2 = 72;
	*(u64*)(r9 - 8) = r2;
	r2 = 77;
	*(u64*)(r1 - 16) = r2;
	exit;
l0_%=:
''')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, force=True)
    unittest.main()
