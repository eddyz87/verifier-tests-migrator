#!/usr/bin/python3

import unittest
from rewrite import convert_string, Options

class Tests(unittest.TestCase):
    def _aux(self, input, expected_output):
        output = convert_string(input, Options())
        self.maxDiff = None
        self.assertMultiLineEqual(expected_output, output,)

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

struct map_struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, long long);
	__type(value, struct test_val);
} map_hash_48b SEC(".maps");

/* invalid and of negative number */
SEC("socket")
__naked
__failure
__msg("R0 max value is outside of the allowed memory range")
__needs_efficient_unaligned_access
void invalid_and_of_negative_number(void)
{
	asm volatile (
	"*(u64*)(r10 -8) = 0;"
	"r2 = r10;"
	"r2 += %[__imm_0];"
	"r1 = %[map_hash_48b] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto l0_0;"
	"r1 = *(u8*)(r0 +0);"
	"r1 &= -4;"
	"r1 <<= 2;"
	"r0 += r1;"
"l0_0:"
	"*(u64*)(r0 +0) = %[test_val_foo_offset];"
	"exit;"
	:
	: [__imm_0]"i"(-8 + 2),
	  [test_val_foo_offset]"i"(offsetof(struct test_val, foo)),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(map_hash_48b)
	: __clobber_all);
}
'''.lstrip())

if __name__ == '__main__':
    unittest.main()
