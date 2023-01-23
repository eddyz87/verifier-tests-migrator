### Installing dependencies

Tested with Python 3.10.6.

```bash
git clone git@github.com:eddyz87/verifier-tests-migrator.git
cd verifier-tests-migrator
# Get the C grammar dependency:
#   https://github.com/tree-sitter/tree-sitter-c
git submodule init
git submodule update
# Install python dependencies
pip3 install -r requirements.txt
# Build C grammar
./build.py
```

### Sanity check

```bash
./tests.py
...........WARNING:root:Can't convert BPF_LD_IMM64()
DEBUG:root:
Errors:
  BPF_LD_IMM64                  : None
Parse tree:
call_expression:
  identifier: BPF_LD_IMM64
  argument_list:

.........
----------------------------------------------------------------------
Ran 20 tests in 0.072s

OK
```

### Execution

Usage:

```bash
usage: rewrite.py [--debug]
                  [--newlines]
                  [--replace-st-mem]
                  file_name

C code for converted test cases is printed to stdout.

positional arguments:
  file_name            the name of the file to convert

options:
  --debug              print some debug info
  --newlines           add \n after each asm instruction
  --replace-st-mem     replace BPF_ST_MEM insns with pairs
                       of MOV/BPF_STX_MEM instructions.
```

Example:

```bash
./rewrite.py ${kernel}/tools/testing/selftests/bpf/verifier/and.c
```

Output:

```c
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

__description("invalid and of negative number")
__failure __msg("R0 max value is outside of the allowed memory range")
__failure_unpriv
__flag(BPF_F_ANY_ALIGNMENT)
SEC("socket")
__naked void invalid_and_of_negative_number(void)
{
        asm volatile (
"       *(u64*)(r10 - 8) = 0;                           \
        r2 = r10;                                       \
        r2 += -8;                                       \
        r1 = %[map_hash_48b] ll;                        \
        call %[bpf_map_lookup_elem];                    \
        if r0 == 0 goto l0_%=;                          \
        r1 = *(u8*)(r0 + 0);                            \
        r1 &= -4;                                       \
        r1 <<= 2;                                       \
        r0 += r1;                                       \
l0_%=:                                                  \
        // yes, label is misplaced in the original      \
        *(u64*)(r0 + 0) = %[test_val_foo_offset];       \
        exit;                                           \
"       :
        : [test_val_foo_offset]"i"(offsetof(struct test_val, foo)),
          __imm(bpf_map_lookup_elem),
          __imm_addr(map_hash_48b)
        : __clobber_all);
}
...
```
