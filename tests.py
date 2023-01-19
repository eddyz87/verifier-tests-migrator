#!/usr/bin/python3

import logging
import unittest
from rewrite import convert_string, Options

class Tests(unittest.TestCase):
    def _aux(self, input, expected_output):
        output = convert_string(input, Options())
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
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
	BPF_CALL_REL(1),
	BPF_EXIT_INSN(),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr = "R0 max value is outside of the allowed memory range",
	.errstr_unpriv = "abra-cadabra",
	.result = REJECT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
''', '''
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

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
__description("invalid and of negative number")
__failure __msg("R0 max value is outside of the allowed memory range")
__msg_unpriv("abra-cadabra")
__flag(BPF_F_ANY_ALIGNMENT)
SEC("socket")
__naked void invalid_and_of_negative_number(void)
{
	asm volatile (
	"*(u64*)(r10 - 8) = 0;"
	"r2 = r10;"
	"r2 += %[__imm_0];"
	"r1 = %[map_hash_48b] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto l0_%=;"
	"r1 = *(u8*)(r0 + 0);"
"l0_%=:"
	"r1 &= -4;"
	"r1 <<= 2;"
	"r1 %%= 2;"
	"r1 |= 2;"
	"r0 += r1;"
	"r1 = -r1;"
	"w1 = -w1;"
	"r2 = -r2;"
	"w2 = -w2;"
	// invalid LD_MAP_FD (it is not patched)
	".8byte %[ld_map_fd];"
	".8byte 0;"
	".8byte %[ld_map_fd_1];"
	".8byte 0;"
	// comment
	"*(u64*)(r0 + 0) = %[test_val_foo_offset];"
	"call l1_%=;"
	"exit;"
"l1_%=:"
	"exit;"
	:
	: [__imm_0]"i"(-8 + 2),
	  [test_val_foo_offset]"i"(offsetof(struct test_val, foo)),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b),
	  __imm_insn(ld_map_fd, BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_7, BPF_PSEUDO_MAP_FD, 0, 32)),
	  __imm_insn(ld_map_fd_1, BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_8, BPF_PSEUDO_MAP_FD, 0, 42))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

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
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, long long);
} map_hash_8b SEC(".maps");

__description("dsize")
__success __success_unpriv
SEC("socket")
__naked void dsize(void)
{
	asm volatile (
	"r1 = %[map_hash_8b] ll;"
	"exit;"
	"r1 = %[map_hash_8b] ll;"
	"exit;"
	"r1 = %[map_hash_8b] ll;"
	"exit;"
	:
	: __imm_addr(map_hash_8b)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

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
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__description("dsize2")
__success __success_unpriv
SEC("socket")
__naked void dsize2(void)
{
	asm volatile (
"l0_%=:"
	"r1 = 0 ll;"
	"goto l0_%=;"
	"r1 = 0 ll;"
	"goto l0_%=;"
	:
	:
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
'''.lstrip())

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
	},
	.result = ACCEPT,
},
''',
                  '''
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__description("atomic")
__success __success_unpriv
SEC("socket")
__naked void atomic(void)
{
	asm volatile (
	"r1 = atomic_fetch_add((u64 *)(r10 - 8), r1);"
	"r2 = atomic_fetch_and((u64 *)(r10 - 8), r2);"
	//
	"w3 = atomic_fetch_or((u32 *)(r10 - 8), w3);"
	"w4 = atomic_fetch_xor((u32 *)(r10 - 8), w4);"
	//
	"lock *(u32 *)(r10 - 16) += w1;"
	"lock *(u32 *)(r10 - 16) &= w2;"
	//
	"lock *(u64 *)(r10 - 16) |= r3;"
	"lock *(u64 *)(r10 - 16) ^= r4;"
	//
	"r1 = xchg_64(r10 - 8, r1);"
	"w1 = xchg32_32(w10 - 4, w1);"
	//
	"r0 = cmpxchg_64(r10 - 8, r0, r1);"
	"w0 = cmpxchg32_32(r10 - 4, w0, w1);"
	:
	:
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

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
	/* 3c */
	BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH, BPF_REG_10, BPF_REG_1, -8),
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
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* 1a */ /* 2a */
/* 3a */
__description("atomic")
/* 1e */ /* 2e */
/* 3e */
__failure
/* 1g */ /* 2g */
/* 3g */
__msg('foo')
/* 1f */ /* 2f */
/* 3f */
__failure_unpriv
/* 1h */ /* 2h */
/* 3h */
__msg_unpriv('bar')
/* 1j */ /* 2j */
/* 3j */
__flag(BPF_F_ANY_ALIGNMENT)
SEC("socket")
__naked void atomic(void)
{
	/* 1b */ /* 2b */
	/* 3b */
	asm volatile (
	/* 1c */ /* 2c */
	/* 3c */
	"r1 = atomic_fetch_add((u64 *)(r10 - 8), r1);"
	/* 1d */ /* 2d */
	/* 3d */
	:
	:
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

    def test_off(self):
        self._aux('''
{
	"imm",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, offsetof(struct foo, bar)),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -offsetof(struct foo, bar)),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 42),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -7),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, -foo, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_OR , BPF_REG_10, BPF_REG_3, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_10, BPF_REG_1, -foo),
	BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -foo),
	},
	.result = REJECT,
},
''',
                  '''
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__description("imm")
__failure __failure_unpriv
SEC("socket")
__naked void imm(void)
{
	asm volatile (
	"r0 = *(u64*)(r1 + %[foo_bar_offset]);"
	"r0 = *(u64*)(r1 - %[foo_bar_offset]);"
	"r0 = *(u64*)(r1 + 42);"
	"r0 = *(u64*)(r1 - 7);"
	"*(u64*)(r0 - %[foo]) = -8;"
	"*(u64*)(r0 - %[foo]) = r1;"
	"lock *(u64 *)(r10 - %[foo]) |= r3;"
	"r1 = xchg_64(r10 - %[foo], r1);"
	"r0 = cmpxchg_64(r10 - %[foo], r0, r1);"
	:
	: [foo_bar_offset]"i"(offsetof(struct foo, bar)),
	  __imm(foo)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

    def test_result_attrs(self):
        self._aux('''
{ "t1", },
{ "t2", .result = ACCEPT, },
{ "t3", .result = VERBOSE_ACCEPT, },
{ "t4", .result = REJECT, },
{ "t5", .result = ACCEPT, .errstr = "x" },
{ "t6", .result = ACCEPT, .errstr = "x", .result_unpriv = REJECT, .errstr_unpriv = "y" },
{ "t7", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_SOCKET_FILTER },
{ "t8", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_CGROUP_SKB },
{ "t9", .result = ACCEPT, .prog_type = BPF_PROG_TYPE_LSM },
''',
                  '''
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__description("t1")
__failure __failure_unpriv
SEC("socket")
__naked void t1(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t2")
__success __success_unpriv
SEC("socket")
__naked void t2(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t3")
__success __success_unpriv
__log_level(2)
SEC("socket")
__naked void t3(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t4")
__failure __failure_unpriv
SEC("socket")
__naked void t4(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t5")
__success __msg("x")
__success_unpriv
SEC("socket")
__naked void t5(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t6")
__success __msg("x")
__failure_unpriv __msg_unpriv("y")
SEC("socket")
__naked void t6(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t7")
__success __success_unpriv
SEC("socket")
__naked void t7(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t8")
__success __success_unpriv
SEC("cgroup/skb")
__naked void t8(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

__description("t9")
__success
SEC("lsm")
__naked void t9(void)
{
	asm volatile (
""	:
	:
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

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
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

__description("imm")
__success __success_unpriv
SEC("socket")
__naked void imm(void)
{
	asm volatile (
	".8byte %[alu64_imm];"
	".8byte %[alu64_reg];"
	"NOT CONVERTED: BPF_LD_IMM64()"
	:
	: __imm_insn(alu64_imm, BPF_ALU64_IMM(12)),
	  __imm_insn(alu64_reg, BPF_ALU64_REG(CAPIBARA, BPF_REG_1, BPF_REG_2))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
''')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, force=True)
    unittest.main()
