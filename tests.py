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
	"invalid and of negative number",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8 + 2),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
	BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_1, -4),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
	// comment
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, offsetof(struct test_val, foo)),
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

/* invalid and of negative number */
__naked __always_inline
void invalid_and_of_negative_number_body(void)
{
	asm volatile (
	"*(u64*)(r10 -8) = 0;"
	"r2 = r10;"
	"r2 += %[__imm_0];"
	"r1 = %[map_hash_48b] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto l0_%=;"
	"r1 = *(u8*)(r0 +0);"
	"r1 &= -4;"
	"r1 <<= 2;"
	"r0 += r1;"
"l0_%=:"
	// comment
	"*(u64*)(r0 +0) = %[test_val_foo_offset];"
	"exit;"
	:
	: [__imm_0]"i"(-8 + 2),
	  [test_val_foo_offset]"i"(offsetof(struct test_val, foo)),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b)
	: __clobber_all);
}

SEC("socket")
__failure __needs_efficient_unaligned_access
__msg("R0 max value is outside of the allowed memory range")
void invalid_and_of_negative_number(void)
{
	invalid_and_of_negative_number_body();
}

SEC("socket")
__unpriv __failure __msg("abra-cadabra") __needs_efficient_unaligned_access
void invalid_and_of_negative_number_unpriv(void)
{
	invalid_and_of_negative_number_body();
}
'''.lstrip())

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

/* dsize */
SEC("socket")
__naked __priv_and_unpriv
void dsize(void)
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
'''.lstrip())

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

/* dsize2 */
SEC("socket")
__naked __priv_and_unpriv
void dsize2(void)
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

/* atomic */
SEC("socket")
__naked __priv_and_unpriv
void atomic(void)
{
	asm volatile (
	"r1 = atomic_fetch_add((u64 *)(r10 -8), r1)"
	"r2 = atomic_fetch_and((u64 *)(r10 -8), r2)"
	//
	"w3 = atomic_fetch_or((u32 *)(r10 -8), w3)"
	"w4 = atomic_fetch_xor((u32 *)(r10 -8), w4)"
	//
	"lock *(u32 *)(r10 -16) += w1"
	"lock *(u32 *)(r10 -16) &= w2"
	//
	"lock *(u64 *)(r10 -16) |= r3"
	"lock *(u64 *)(r10 -16) ^= r4"
	//
	"r1 = xchg_64(r10 -8, r1)"
	"w1 = xchg32_32(w10 -4, w1)"
	//
	"r0 = cmpxchg_64(r10 -8, r0, r1)"
	"w0 = cmpxchg32_32(r10 -4, w0, w1)"
	:
	:
	: __clobber_all);
}
''')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, force=True)
    unittest.main()
