%% ebpf_opcodes.hrl — BPF instruction opcode constants (from TR-01)
%% Auto-derived from linux/bpf.h, formatted for Erlang macros.

-ifndef(EBPF_OPCODES_HRL).
-define(EBPF_OPCODES_HRL, true).

%% === Instruction classes (3 bits) ===
-define(BPF_LD,    16#00).
-define(BPF_LDX,   16#01).
-define(BPF_ST,    16#02).
-define(BPF_STX,   16#03).
-define(BPF_ALU,   16#04).
-define(BPF_JMP,   16#05).
-define(BPF_JMP32, 16#06).
-define(BPF_ALU64, 16#07).

%% === ALU operation codes (4 bits, shifted left 4) ===
-define(BPF_ADD,  16#00).
-define(BPF_SUB,  16#10).
-define(BPF_MUL,  16#20).
-define(BPF_DIV,  16#30).
-define(BPF_OR,   16#40).
-define(BPF_AND,  16#50).
-define(BPF_LSH,  16#60).
-define(BPF_RSH,  16#70).
-define(BPF_NEG,  16#80).
-define(BPF_MOD,  16#90).
-define(BPF_XOR,  16#a0).
-define(BPF_MOV,  16#b0).
-define(BPF_ARSH, 16#c0).
-define(BPF_END,  16#d0).

%% === JMP operation codes (4 bits, shifted left 4) ===
-define(BPF_JA,   16#00).
-define(BPF_JEQ,  16#10).
-define(BPF_JGT,  16#20).
-define(BPF_JGE,  16#30).
-define(BPF_JSET, 16#40).
-define(BPF_JNE,  16#50).
-define(BPF_JSGT, 16#60).
-define(BPF_JSGE, 16#70).
-define(BPF_CALL, 16#80).
-define(BPF_EXIT, 16#90).
-define(BPF_JLT,  16#a0).
-define(BPF_JLE,  16#b0).
-define(BPF_JSLT, 16#c0).
-define(BPF_JSLE, 16#d0).

%% === Endian direction (bit 3 of opcode) ===
-define(BPF_TO_LE, 16#00). %% Convert to little-endian
-define(BPF_TO_BE, 16#08). %% Convert to big-endian

%% === Source operand mode (1 bit, position 3) ===
-define(BPF_K,   16#00).   %% Immediate (imm field)
-define(BPF_X,   16#08).   %% Register (src field)

%% === Memory access sizes (2 bits) ===
-define(BPF_W,   16#00).   %% 32-bit word
-define(BPF_H,   16#08).   %% 16-bit half-word
-define(BPF_B,   16#10).   %% 8-bit byte
-define(BPF_DW,  16#18).   %% 64-bit double-word

%% === Memory access modes ===
-define(BPF_MEM, 16#60).   %% Regular memory access
-define(BPF_IMM, 16#00).   %% Immediate (used for LD_IMM64)

%% === Composed opcodes: ALU64 + IMM ===
-define(OP_ADD64_IMM,  (?BPF_ALU64 bor ?BPF_ADD  bor ?BPF_K)).   %% 0x07
-define(OP_ADD64_REG,  (?BPF_ALU64 bor ?BPF_ADD  bor ?BPF_X)).   %% 0x0f
-define(OP_SUB64_IMM,  (?BPF_ALU64 bor ?BPF_SUB  bor ?BPF_K)).   %% 0x17
-define(OP_SUB64_REG,  (?BPF_ALU64 bor ?BPF_SUB  bor ?BPF_X)).   %% 0x1f
-define(OP_MUL64_IMM,  (?BPF_ALU64 bor ?BPF_MUL  bor ?BPF_K)).   %% 0x27
-define(OP_MUL64_REG,  (?BPF_ALU64 bor ?BPF_MUL  bor ?BPF_X)).   %% 0x2f
-define(OP_DIV64_IMM,  (?BPF_ALU64 bor ?BPF_DIV  bor ?BPF_K)).   %% 0x37
-define(OP_DIV64_REG,  (?BPF_ALU64 bor ?BPF_DIV  bor ?BPF_X)).   %% 0x3f
-define(OP_OR64_IMM,   (?BPF_ALU64 bor ?BPF_OR   bor ?BPF_K)).   %% 0x47
-define(OP_OR64_REG,   (?BPF_ALU64 bor ?BPF_OR   bor ?BPF_X)).   %% 0x4f
-define(OP_AND64_IMM,  (?BPF_ALU64 bor ?BPF_AND  bor ?BPF_K)).   %% 0x57
-define(OP_AND64_REG,  (?BPF_ALU64 bor ?BPF_AND  bor ?BPF_X)).   %% 0x5f
-define(OP_LSH64_IMM,  (?BPF_ALU64 bor ?BPF_LSH  bor ?BPF_K)).   %% 0x67
-define(OP_LSH64_REG,  (?BPF_ALU64 bor ?BPF_LSH  bor ?BPF_X)).   %% 0x6f
-define(OP_RSH64_IMM,  (?BPF_ALU64 bor ?BPF_RSH  bor ?BPF_K)).   %% 0x77
-define(OP_RSH64_REG,  (?BPF_ALU64 bor ?BPF_RSH  bor ?BPF_X)).   %% 0x7f
-define(OP_NEG64,      (?BPF_ALU64 bor ?BPF_NEG  bor ?BPF_K)).   %% 0x87
-define(OP_MOD64_IMM,  (?BPF_ALU64 bor ?BPF_MOD  bor ?BPF_K)).   %% 0x97
-define(OP_MOD64_REG,  (?BPF_ALU64 bor ?BPF_MOD  bor ?BPF_X)).   %% 0x9f
-define(OP_XOR64_IMM,  (?BPF_ALU64 bor ?BPF_XOR  bor ?BPF_K)).   %% 0xa7
-define(OP_XOR64_REG,  (?BPF_ALU64 bor ?BPF_XOR  bor ?BPF_X)).   %% 0xaf
-define(OP_MOV64_IMM,  (?BPF_ALU64 bor ?BPF_MOV  bor ?BPF_K)).   %% 0xb7
-define(OP_MOV64_REG,  (?BPF_ALU64 bor ?BPF_MOV  bor ?BPF_X)).   %% 0xbf
-define(OP_ARSH64_IMM, (?BPF_ALU64 bor ?BPF_ARSH bor ?BPF_K)).   %% 0xc7
-define(OP_ARSH64_REG, (?BPF_ALU64 bor ?BPF_ARSH bor ?BPF_X)).   %% 0xcf

%% === Composed opcodes: ALU32 + IMM ===
-define(OP_ADD32_IMM,  (?BPF_ALU bor ?BPF_ADD  bor ?BPF_K)).   %% 0x04
-define(OP_ADD32_REG,  (?BPF_ALU bor ?BPF_ADD  bor ?BPF_X)).   %% 0x0c
-define(OP_SUB32_IMM,  (?BPF_ALU bor ?BPF_SUB  bor ?BPF_K)).   %% 0x14
-define(OP_SUB32_REG,  (?BPF_ALU bor ?BPF_SUB  bor ?BPF_X)).   %% 0x1c
-define(OP_MUL32_IMM,  (?BPF_ALU bor ?BPF_MUL  bor ?BPF_K)).   %% 0x24
-define(OP_MUL32_REG,  (?BPF_ALU bor ?BPF_MUL  bor ?BPF_X)).   %% 0x2c
-define(OP_DIV32_IMM,  (?BPF_ALU bor ?BPF_DIV  bor ?BPF_K)).   %% 0x34
-define(OP_DIV32_REG,  (?BPF_ALU bor ?BPF_DIV  bor ?BPF_X)).   %% 0x3c
-define(OP_OR32_IMM,   (?BPF_ALU bor ?BPF_OR   bor ?BPF_K)).   %% 0x44
-define(OP_OR32_REG,   (?BPF_ALU bor ?BPF_OR   bor ?BPF_X)).   %% 0x4c
-define(OP_AND32_IMM,  (?BPF_ALU bor ?BPF_AND  bor ?BPF_K)).   %% 0x54
-define(OP_AND32_REG,  (?BPF_ALU bor ?BPF_AND  bor ?BPF_X)).   %% 0x5c
-define(OP_LSH32_IMM,  (?BPF_ALU bor ?BPF_LSH  bor ?BPF_K)).   %% 0x64
-define(OP_LSH32_REG,  (?BPF_ALU bor ?BPF_LSH  bor ?BPF_X)).   %% 0x6c
-define(OP_RSH32_IMM,  (?BPF_ALU bor ?BPF_RSH  bor ?BPF_K)).   %% 0x74
-define(OP_RSH32_REG,  (?BPF_ALU bor ?BPF_RSH  bor ?BPF_X)).   %% 0x7c
-define(OP_NEG32,      (?BPF_ALU bor ?BPF_NEG  bor ?BPF_K)).   %% 0x84
-define(OP_MOD32_IMM,  (?BPF_ALU bor ?BPF_MOD  bor ?BPF_K)).   %% 0x94
-define(OP_MOD32_REG,  (?BPF_ALU bor ?BPF_MOD  bor ?BPF_X)).   %% 0x9c
-define(OP_XOR32_IMM,  (?BPF_ALU bor ?BPF_XOR  bor ?BPF_K)).   %% 0xa4
-define(OP_XOR32_REG,  (?BPF_ALU bor ?BPF_XOR  bor ?BPF_X)).   %% 0xac
-define(OP_MOV32_IMM,  (?BPF_ALU bor ?BPF_MOV  bor ?BPF_K)).   %% 0xb4
-define(OP_MOV32_REG,  (?BPF_ALU bor ?BPF_MOV  bor ?BPF_X)).   %% 0xbc
-define(OP_ARSH32_IMM, (?BPF_ALU bor ?BPF_ARSH bor ?BPF_K)).   %% 0xc4
-define(OP_ARSH32_REG, (?BPF_ALU bor ?BPF_ARSH bor ?BPF_X)).   %% 0xcc

%% === Composed opcodes: Endian byte-swap ===
%% imm field = 16, 32, or 64 (bit width)
-define(OP_LE,  (?BPF_ALU bor ?BPF_END bor ?BPF_TO_LE)).   %% 0xd4
-define(OP_BE,  (?BPF_ALU bor ?BPF_END bor ?BPF_TO_BE)).   %% 0xdc

%% === Composed opcodes: Memory LDX ===
-define(OP_LDXW,  (?BPF_LDX bor ?BPF_MEM bor ?BPF_W)).    %% 0x61
-define(OP_LDXH,  (?BPF_LDX bor ?BPF_MEM bor ?BPF_H)).    %% 0x69
-define(OP_LDXB,  (?BPF_LDX bor ?BPF_MEM bor ?BPF_B)).    %% 0x71
-define(OP_LDXDW, (?BPF_LDX bor ?BPF_MEM bor ?BPF_DW)).   %% 0x79

%% === Composed opcodes: Memory STX ===
-define(OP_STXW,  (?BPF_STX bor ?BPF_MEM bor ?BPF_W)).    %% 0x63
-define(OP_STXH,  (?BPF_STX bor ?BPF_MEM bor ?BPF_H)).    %% 0x6b
-define(OP_STXB,  (?BPF_STX bor ?BPF_MEM bor ?BPF_B)).    %% 0x73
-define(OP_STXDW, (?BPF_STX bor ?BPF_MEM bor ?BPF_DW)).   %% 0x7b

%% === Composed opcodes: Memory ST (immediate) ===
-define(OP_STW,  (?BPF_ST bor ?BPF_MEM bor ?BPF_W)).      %% 0x62
-define(OP_STH,  (?BPF_ST bor ?BPF_MEM bor ?BPF_H)).      %% 0x6a
-define(OP_STB,  (?BPF_ST bor ?BPF_MEM bor ?BPF_B)).      %% 0x72
-define(OP_STDW, (?BPF_ST bor ?BPF_MEM bor ?BPF_DW)).     %% 0x7a

%% === Composed opcodes: JMP64 ===
-define(OP_JA,        (?BPF_JMP bor ?BPF_JA   bor ?BPF_K)).   %% 0x05
-define(OP_JEQ_IMM,   (?BPF_JMP bor ?BPF_JEQ  bor ?BPF_K)).   %% 0x15
-define(OP_JEQ_REG,   (?BPF_JMP bor ?BPF_JEQ  bor ?BPF_X)).   %% 0x1d
-define(OP_JGT_IMM,   (?BPF_JMP bor ?BPF_JGT  bor ?BPF_K)).   %% 0x25
-define(OP_JGT_REG,   (?BPF_JMP bor ?BPF_JGT  bor ?BPF_X)).   %% 0x2d
-define(OP_JGE_IMM,   (?BPF_JMP bor ?BPF_JGE  bor ?BPF_K)).   %% 0x35
-define(OP_JGE_REG,   (?BPF_JMP bor ?BPF_JGE  bor ?BPF_X)).   %% 0x3d
-define(OP_JSET_IMM,  (?BPF_JMP bor ?BPF_JSET bor ?BPF_K)).   %% 0x45
-define(OP_JSET_REG,  (?BPF_JMP bor ?BPF_JSET bor ?BPF_X)).   %% 0x4d
-define(OP_JNE_IMM,   (?BPF_JMP bor ?BPF_JNE  bor ?BPF_K)).   %% 0x55
-define(OP_JNE_REG,   (?BPF_JMP bor ?BPF_JNE  bor ?BPF_X)).   %% 0x5d
-define(OP_JSGT_IMM,  (?BPF_JMP bor ?BPF_JSGT bor ?BPF_K)).   %% 0x65
-define(OP_JSGT_REG,  (?BPF_JMP bor ?BPF_JSGT bor ?BPF_X)).   %% 0x6d
-define(OP_JSGE_IMM,  (?BPF_JMP bor ?BPF_JSGE bor ?BPF_K)).   %% 0x75
-define(OP_JSGE_REG,  (?BPF_JMP bor ?BPF_JSGE bor ?BPF_X)).   %% 0x7d
-define(OP_CALL,      (?BPF_JMP bor ?BPF_CALL bor ?BPF_K)).   %% 0x85
-define(OP_EXIT,      (?BPF_JMP bor ?BPF_EXIT bor ?BPF_K)).   %% 0x95
-define(OP_JLT_IMM,   (?BPF_JMP bor ?BPF_JLT  bor ?BPF_K)).   %% 0xa5
-define(OP_JLT_REG,   (?BPF_JMP bor ?BPF_JLT  bor ?BPF_X)).   %% 0xad
-define(OP_JLE_IMM,   (?BPF_JMP bor ?BPF_JLE  bor ?BPF_K)).   %% 0xb5
-define(OP_JLE_REG,   (?BPF_JMP bor ?BPF_JLE  bor ?BPF_X)).   %% 0xbd
-define(OP_JSLT_IMM,  (?BPF_JMP bor ?BPF_JSLT bor ?BPF_K)).   %% 0xc5
-define(OP_JSLT_REG,  (?BPF_JMP bor ?BPF_JSLT bor ?BPF_X)).   %% 0xcd
-define(OP_JSLE_IMM,  (?BPF_JMP bor ?BPF_JSLE bor ?BPF_K)).   %% 0xd5
-define(OP_JSLE_REG,  (?BPF_JMP bor ?BPF_JSLE bor ?BPF_X)).   %% 0xdd

%% === Composed opcodes: JMP32 ===
-define(OP_JEQ32_IMM,  (?BPF_JMP32 bor ?BPF_JEQ  bor ?BPF_K)).  %% 0x16
-define(OP_JEQ32_REG,  (?BPF_JMP32 bor ?BPF_JEQ  bor ?BPF_X)).  %% 0x1e
-define(OP_JGT32_IMM,  (?BPF_JMP32 bor ?BPF_JGT  bor ?BPF_K)).  %% 0x26
-define(OP_JGT32_REG,  (?BPF_JMP32 bor ?BPF_JGT  bor ?BPF_X)).  %% 0x2e
-define(OP_JGE32_IMM,  (?BPF_JMP32 bor ?BPF_JGE  bor ?BPF_K)).  %% 0x36
-define(OP_JGE32_REG,  (?BPF_JMP32 bor ?BPF_JGE  bor ?BPF_X)).  %% 0x3e
-define(OP_JSET32_IMM, (?BPF_JMP32 bor ?BPF_JSET bor ?BPF_K)).  %% 0x46
-define(OP_JSET32_REG, (?BPF_JMP32 bor ?BPF_JSET bor ?BPF_X)).  %% 0x4e
-define(OP_JNE32_IMM,  (?BPF_JMP32 bor ?BPF_JNE  bor ?BPF_K)).  %% 0x56
-define(OP_JNE32_REG,  (?BPF_JMP32 bor ?BPF_JNE  bor ?BPF_X)).  %% 0x5e
-define(OP_JSGT32_IMM, (?BPF_JMP32 bor ?BPF_JSGT bor ?BPF_K)).  %% 0x66
-define(OP_JSGT32_REG, (?BPF_JMP32 bor ?BPF_JSGT bor ?BPF_X)).  %% 0x6e
-define(OP_JSGE32_IMM, (?BPF_JMP32 bor ?BPF_JSGE bor ?BPF_K)).  %% 0x76
-define(OP_JSGE32_REG, (?BPF_JMP32 bor ?BPF_JSGE bor ?BPF_X)).  %% 0x7e
-define(OP_JLT32_IMM,  (?BPF_JMP32 bor ?BPF_JLT  bor ?BPF_K)).  %% 0xa6
-define(OP_JLT32_REG,  (?BPF_JMP32 bor ?BPF_JLT  bor ?BPF_X)).  %% 0xae
-define(OP_JLE32_IMM,  (?BPF_JMP32 bor ?BPF_JLE  bor ?BPF_K)).  %% 0xb6
-define(OP_JLE32_REG,  (?BPF_JMP32 bor ?BPF_JLE  bor ?BPF_X)).  %% 0xbe
-define(OP_JSLT32_IMM, (?BPF_JMP32 bor ?BPF_JSLT bor ?BPF_K)).  %% 0xc6
-define(OP_JSLT32_REG, (?BPF_JMP32 bor ?BPF_JSLT bor ?BPF_X)).  %% 0xce
-define(OP_JSLE32_IMM, (?BPF_JMP32 bor ?BPF_JSLE bor ?BPF_K)).  %% 0xd6
-define(OP_JSLE32_REG, (?BPF_JMP32 bor ?BPF_JSLE bor ?BPF_X)).  %% 0xde

%% === 64-bit immediate load ===
-define(OP_LD_IMM64, (?BPF_LD bor ?BPF_IMM bor ?BPF_DW)).     %% 0x18

%% === Pseudo map FD source values (in src field of LD_IMM64) ===
-define(BPF_PSEUDO_MAP_FD,    1).
-define(BPF_PSEUDO_MAP_VALUE, 2).

%% === BPF register numbers ===
-define(BPF_REG_0,  0).
-define(BPF_REG_1,  1).
-define(BPF_REG_2,  2).
-define(BPF_REG_3,  3).
-define(BPF_REG_4,  4).
-define(BPF_REG_5,  5).
-define(BPF_REG_6,  6).
-define(BPF_REG_7,  7).
-define(BPF_REG_8,  8).
-define(BPF_REG_9,  9).
-define(BPF_REG_10, 10).

%% === Encoding macro: 8-byte bpf_insn ===
-define(INSN(Code, Dst, Src, Off, Imm),
    <<(Code):8, ((Src) bsl 4 bor (Dst)):8,
      (Off):16/signed-little, (Imm):32/signed-little>>).

-endif. %% EBPF_OPCODES_HRL
