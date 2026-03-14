%% @doc BPF instruction encoding and decoding.
%%
%% Each function encodes a single BPF instruction as an 8-byte binary
%% (or 16-byte for ld_map_fd/ld64_imm).  The wire format follows
%% struct bpf_insn from linux/bpf.h:
%%
%%   struct bpf_insn {
%%       __u8  code;
%%       __u8  dst_reg:4;
%%       __u8  src_reg:4;
%%       __s16 off;
%%       __s32 imm;
%%   };
%%
%% Reference: TR-01 (eBPF Instruction Set Encoding)
-module(ebpf_insn).

-include("ebpf_opcodes.hrl").

%% Encoding API
-export([
    %% ALU64 (immediate)
    add64_imm/2, sub64_imm/2, mul64_imm/2, div64_imm/2,
    or64_imm/2, and64_imm/2, lsh64_imm/2, rsh64_imm/2,
    neg64/1, mod64_imm/2, xor64_imm/2, mov64_imm/2, arsh64_imm/2,
    %% ALU64 (register)
    add64_reg/2, sub64_reg/2, mul64_reg/2, div64_reg/2,
    or64_reg/2, and64_reg/2, lsh64_reg/2, rsh64_reg/2,
    mod64_reg/2, xor64_reg/2, mov64_reg/2, arsh64_reg/2,
    %% ALU32 (immediate)
    add32_imm/2, sub32_imm/2, mul32_imm/2, div32_imm/2,
    or32_imm/2, and32_imm/2, lsh32_imm/2, rsh32_imm/2,
    neg32/1, mod32_imm/2, xor32_imm/2, mov32_imm/2, arsh32_imm/2,
    %% ALU32 (register)
    add32_reg/2, sub32_reg/2, mul32_reg/2, div32_reg/2,
    or32_reg/2, and32_reg/2, lsh32_reg/2, rsh32_reg/2,
    mod32_reg/2, xor32_reg/2, mov32_reg/2, arsh32_reg/2,
    %% Memory load (LDX)
    ldxw/3, ldxh/3, ldxb/3, ldxdw/3,
    %% Memory store register (STX)
    stxw/3, stxh/3, stxb/3, stxdw/3,
    %% Memory store immediate (ST)
    stw/3, sth/3, stb/3, stdw/3,
    %% 64-bit immediate load
    ld64_imm/2, ld_map_fd/2,
    %% Jump
    ja/1,
    jeq_imm/3, jeq_reg/3, jgt_imm/3, jgt_reg/3,
    jge_imm/3, jge_reg/3, jset_imm/3, jset_reg/3,
    jne_imm/3, jne_reg/3, jsgt_imm/3, jsgt_reg/3,
    jsge_imm/3, jsge_reg/3, jlt_imm/3, jlt_reg/3,
    jle_imm/3, jle_reg/3, jslt_imm/3, jslt_reg/3,
    jsle_imm/3, jsle_reg/3,
    %% JMP32
    jeq32_imm/3, jeq32_reg/3, jgt32_imm/3, jgt32_reg/3,
    jge32_imm/3, jge32_reg/3, jne32_imm/3, jne32_reg/3,
    jlt32_imm/3, jlt32_reg/3, jle32_imm/3, jle32_reg/3,
    jsgt32_imm/3, jsgt32_reg/3, jsge32_imm/3, jsge32_reg/3,
    jslt32_imm/3, jslt32_reg/3, jsle32_imm/3, jsle32_reg/3,
    jset32_imm/3, jset32_reg/3,
    %% Endian byte-swap
    be16/1, be32/1, be64/1, le16/1, le32/1, le64/1,
    %% Special
    call/1, exit_insn/0,
    %% Decoding
    decode/1,
    %% Assembly
    assemble/1,
    %% uBPF compatibility
    patch_for_ubpf/1
]).

-export_type([reg/0, insn/0]).

-type reg() :: 0..10.
-type insn() :: binary().  %% 8 or 16 bytes

%%% ===================================================================
%%% ALU64 — Immediate
%%% ===================================================================

-spec add64_imm(reg(), integer()) -> insn().
add64_imm(Dst, Imm)  -> ?INSN(?OP_ADD64_IMM,  Dst, 0, 0, Imm).
sub64_imm(Dst, Imm)  -> ?INSN(?OP_SUB64_IMM,  Dst, 0, 0, Imm).
mul64_imm(Dst, Imm)  -> ?INSN(?OP_MUL64_IMM,  Dst, 0, 0, Imm).
div64_imm(Dst, Imm)  -> ?INSN(?OP_DIV64_IMM,  Dst, 0, 0, Imm).
or64_imm(Dst, Imm)   -> ?INSN(?OP_OR64_IMM,   Dst, 0, 0, Imm).
and64_imm(Dst, Imm)  -> ?INSN(?OP_AND64_IMM,  Dst, 0, 0, Imm).
lsh64_imm(Dst, Imm)  -> ?INSN(?OP_LSH64_IMM,  Dst, 0, 0, Imm).
rsh64_imm(Dst, Imm)  -> ?INSN(?OP_RSH64_IMM,  Dst, 0, 0, Imm).
neg64(Dst)            -> ?INSN(?OP_NEG64,       Dst, 0, 0, 0).
mod64_imm(Dst, Imm)  -> ?INSN(?OP_MOD64_IMM,  Dst, 0, 0, Imm).
xor64_imm(Dst, Imm)  -> ?INSN(?OP_XOR64_IMM,  Dst, 0, 0, Imm).
mov64_imm(Dst, Imm)  -> ?INSN(?OP_MOV64_IMM,  Dst, 0, 0, Imm).
arsh64_imm(Dst, Imm) -> ?INSN(?OP_ARSH64_IMM, Dst, 0, 0, Imm).

%%% ===================================================================
%%% ALU64 — Register
%%% ===================================================================

add64_reg(Dst, Src)  -> ?INSN(?OP_ADD64_REG,  Dst, Src, 0, 0).
sub64_reg(Dst, Src)  -> ?INSN(?OP_SUB64_REG,  Dst, Src, 0, 0).
mul64_reg(Dst, Src)  -> ?INSN(?OP_MUL64_REG,  Dst, Src, 0, 0).
div64_reg(Dst, Src)  -> ?INSN(?OP_DIV64_REG,  Dst, Src, 0, 0).
or64_reg(Dst, Src)   -> ?INSN(?OP_OR64_REG,   Dst, Src, 0, 0).
and64_reg(Dst, Src)  -> ?INSN(?OP_AND64_REG,  Dst, Src, 0, 0).
lsh64_reg(Dst, Src)  -> ?INSN(?OP_LSH64_REG,  Dst, Src, 0, 0).
rsh64_reg(Dst, Src)  -> ?INSN(?OP_RSH64_REG,  Dst, Src, 0, 0).
mod64_reg(Dst, Src)  -> ?INSN(?OP_MOD64_REG,  Dst, Src, 0, 0).
xor64_reg(Dst, Src)  -> ?INSN(?OP_XOR64_REG,  Dst, Src, 0, 0).
mov64_reg(Dst, Src)  -> ?INSN(?OP_MOV64_REG,  Dst, Src, 0, 0).
arsh64_reg(Dst, Src) -> ?INSN(?OP_ARSH64_REG, Dst, Src, 0, 0).

%%% ===================================================================
%%% ALU32 — Immediate
%%% ===================================================================

add32_imm(Dst, Imm)  -> ?INSN(?OP_ADD32_IMM,  Dst, 0, 0, Imm).
sub32_imm(Dst, Imm)  -> ?INSN(?OP_SUB32_IMM,  Dst, 0, 0, Imm).
mul32_imm(Dst, Imm)  -> ?INSN(?OP_MUL32_IMM,  Dst, 0, 0, Imm).
div32_imm(Dst, Imm)  -> ?INSN(?OP_DIV32_IMM,  Dst, 0, 0, Imm).
or32_imm(Dst, Imm)   -> ?INSN(?OP_OR32_IMM,   Dst, 0, 0, Imm).
and32_imm(Dst, Imm)  -> ?INSN(?OP_AND32_IMM,  Dst, 0, 0, Imm).
lsh32_imm(Dst, Imm)  -> ?INSN(?OP_LSH32_IMM,  Dst, 0, 0, Imm).
rsh32_imm(Dst, Imm)  -> ?INSN(?OP_RSH32_IMM,  Dst, 0, 0, Imm).
neg32(Dst)            -> ?INSN(?OP_NEG32,       Dst, 0, 0, 0).
mod32_imm(Dst, Imm)  -> ?INSN(?OP_MOD32_IMM,  Dst, 0, 0, Imm).
xor32_imm(Dst, Imm)  -> ?INSN(?OP_XOR32_IMM,  Dst, 0, 0, Imm).
mov32_imm(Dst, Imm)  -> ?INSN(?OP_MOV32_IMM,  Dst, 0, 0, Imm).
arsh32_imm(Dst, Imm) -> ?INSN(?OP_ARSH32_IMM, Dst, 0, 0, Imm).

%%% ===================================================================
%%% ALU32 — Register
%%% ===================================================================

add32_reg(Dst, Src)  -> ?INSN(?OP_ADD32_REG,  Dst, Src, 0, 0).
sub32_reg(Dst, Src)  -> ?INSN(?OP_SUB32_REG,  Dst, Src, 0, 0).
mul32_reg(Dst, Src)  -> ?INSN(?OP_MUL32_REG,  Dst, Src, 0, 0).
div32_reg(Dst, Src)  -> ?INSN(?OP_DIV32_REG,  Dst, Src, 0, 0).
or32_reg(Dst, Src)   -> ?INSN(?OP_OR32_REG,   Dst, Src, 0, 0).
and32_reg(Dst, Src)  -> ?INSN(?OP_AND32_REG,  Dst, Src, 0, 0).
lsh32_reg(Dst, Src)  -> ?INSN(?OP_LSH32_REG,  Dst, Src, 0, 0).
rsh32_reg(Dst, Src)  -> ?INSN(?OP_RSH32_REG,  Dst, Src, 0, 0).
mod32_reg(Dst, Src)  -> ?INSN(?OP_MOD32_REG,  Dst, Src, 0, 0).
xor32_reg(Dst, Src)  -> ?INSN(?OP_XOR32_REG,  Dst, Src, 0, 0).
mov32_reg(Dst, Src)  -> ?INSN(?OP_MOV32_REG,  Dst, Src, 0, 0).
arsh32_reg(Dst, Src) -> ?INSN(?OP_ARSH32_REG, Dst, Src, 0, 0).

%%% ===================================================================
%%% Memory — LDX (load from memory to register)
%%% ldx<size> dst, [src + off]
%%% ===================================================================

ldxw(Dst, Src, Off)  -> ?INSN(?OP_LDXW,  Dst, Src, Off, 0).
ldxh(Dst, Src, Off)  -> ?INSN(?OP_LDXH,  Dst, Src, Off, 0).
ldxb(Dst, Src, Off)  -> ?INSN(?OP_LDXB,  Dst, Src, Off, 0).
ldxdw(Dst, Src, Off) -> ?INSN(?OP_LDXDW, Dst, Src, Off, 0).

%%% ===================================================================
%%% Memory — STX (store register to memory)
%%% stx<size> [dst + off], src
%%% ===================================================================

stxw(Dst, Off, Src)  -> ?INSN(?OP_STXW,  Dst, Src, Off, 0).
stxh(Dst, Off, Src)  -> ?INSN(?OP_STXH,  Dst, Src, Off, 0).
stxb(Dst, Off, Src)  -> ?INSN(?OP_STXB,  Dst, Src, Off, 0).
stxdw(Dst, Off, Src) -> ?INSN(?OP_STXDW, Dst, Src, Off, 0).

%%% ===================================================================
%%% Memory — ST (store immediate to memory)
%%% st<size> [dst + off], imm
%%% ===================================================================

stw(Dst, Off, Imm)  -> ?INSN(?OP_STW,  Dst, 0, Off, Imm).
sth(Dst, Off, Imm)  -> ?INSN(?OP_STH,  Dst, 0, Off, Imm).
stb(Dst, Off, Imm)  -> ?INSN(?OP_STB,  Dst, 0, Off, Imm).
stdw(Dst, Off, Imm) -> ?INSN(?OP_STDW, Dst, 0, Off, Imm).

%%% ===================================================================
%%% 64-bit immediate load (16 bytes — two instruction slots)
%%% ===================================================================

-spec ld64_imm(reg(), integer()) -> insn().
ld64_imm(Dst, Imm) ->
    Lo = Imm band 16#FFFFFFFF,
    Hi = (Imm bsr 32) band 16#FFFFFFFF,
    <<?OP_LD_IMM64, (0 bsl 4 bor Dst), 0:16/signed-little, Lo:32/signed-little,
      0:8, 0:8, 0:16/signed-little, Hi:32/signed-little>>.

-spec ld_map_fd(reg(), integer()) -> insn().
ld_map_fd(Dst, MapFd) ->
    <<?OP_LD_IMM64, (?BPF_PSEUDO_MAP_FD bsl 4 bor Dst), 0:16/signed-little,
      MapFd:32/signed-little,
      0:8, 0:8, 0:16/signed-little, 0:32/signed-little>>.

%%% ===================================================================
%%% Jump — Unconditional
%%% ===================================================================

ja(Off) -> ?INSN(?OP_JA, 0, 0, Off, 0).

%%% ===================================================================
%%% Jump — Conditional (64-bit)
%%% jxx dst, imm/src, +off
%%% ===================================================================

jeq_imm(Dst, Imm, Off)  -> ?INSN(?OP_JEQ_IMM,  Dst, 0, Off, Imm).
jeq_reg(Dst, Src, Off)   -> ?INSN(?OP_JEQ_REG,  Dst, Src, Off, 0).
jgt_imm(Dst, Imm, Off)  -> ?INSN(?OP_JGT_IMM,  Dst, 0, Off, Imm).
jgt_reg(Dst, Src, Off)   -> ?INSN(?OP_JGT_REG,  Dst, Src, Off, 0).
jge_imm(Dst, Imm, Off)  -> ?INSN(?OP_JGE_IMM,  Dst, 0, Off, Imm).
jge_reg(Dst, Src, Off)   -> ?INSN(?OP_JGE_REG,  Dst, Src, Off, 0).
jset_imm(Dst, Imm, Off) -> ?INSN(?OP_JSET_IMM, Dst, 0, Off, Imm).
jset_reg(Dst, Src, Off)  -> ?INSN(?OP_JSET_REG, Dst, Src, Off, 0).
jne_imm(Dst, Imm, Off)  -> ?INSN(?OP_JNE_IMM,  Dst, 0, Off, Imm).
jne_reg(Dst, Src, Off)   -> ?INSN(?OP_JNE_REG,  Dst, Src, Off, 0).
jsgt_imm(Dst, Imm, Off) -> ?INSN(?OP_JSGT_IMM, Dst, 0, Off, Imm).
jsgt_reg(Dst, Src, Off)  -> ?INSN(?OP_JSGT_REG, Dst, Src, Off, 0).
jsge_imm(Dst, Imm, Off) -> ?INSN(?OP_JSGE_IMM, Dst, 0, Off, Imm).
jsge_reg(Dst, Src, Off)  -> ?INSN(?OP_JSGE_REG, Dst, Src, Off, 0).
jlt_imm(Dst, Imm, Off)  -> ?INSN(?OP_JLT_IMM,  Dst, 0, Off, Imm).
jlt_reg(Dst, Src, Off)   -> ?INSN(?OP_JLT_REG,  Dst, Src, Off, 0).
jle_imm(Dst, Imm, Off)  -> ?INSN(?OP_JLE_IMM,  Dst, 0, Off, Imm).
jle_reg(Dst, Src, Off)   -> ?INSN(?OP_JLE_REG,  Dst, Src, Off, 0).
jslt_imm(Dst, Imm, Off) -> ?INSN(?OP_JSLT_IMM, Dst, 0, Off, Imm).
jslt_reg(Dst, Src, Off)  -> ?INSN(?OP_JSLT_REG, Dst, Src, Off, 0).
jsle_imm(Dst, Imm, Off) -> ?INSN(?OP_JSLE_IMM, Dst, 0, Off, Imm).
jsle_reg(Dst, Src, Off)  -> ?INSN(?OP_JSLE_REG, Dst, Src, Off, 0).

%%% ===================================================================
%%% Jump — Conditional (32-bit)
%%% ===================================================================

jeq32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JEQ32_IMM,  Dst, 0, Off, Imm).
jeq32_reg(Dst, Src, Off)   -> ?INSN(?OP_JEQ32_REG,  Dst, Src, Off, 0).
jgt32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JGT32_IMM,  Dst, 0, Off, Imm).
jgt32_reg(Dst, Src, Off)   -> ?INSN(?OP_JGT32_REG,  Dst, Src, Off, 0).
jge32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JGE32_IMM,  Dst, 0, Off, Imm).
jge32_reg(Dst, Src, Off)   -> ?INSN(?OP_JGE32_REG,  Dst, Src, Off, 0).
jset32_imm(Dst, Imm, Off) -> ?INSN(?OP_JSET32_IMM, Dst, 0, Off, Imm).
jset32_reg(Dst, Src, Off)  -> ?INSN(?OP_JSET32_REG, Dst, Src, Off, 0).
jne32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JNE32_IMM,  Dst, 0, Off, Imm).
jne32_reg(Dst, Src, Off)   -> ?INSN(?OP_JNE32_REG,  Dst, Src, Off, 0).
jsgt32_imm(Dst, Imm, Off) -> ?INSN(?OP_JSGT32_IMM, Dst, 0, Off, Imm).
jsgt32_reg(Dst, Src, Off)  -> ?INSN(?OP_JSGT32_REG, Dst, Src, Off, 0).
jsge32_imm(Dst, Imm, Off) -> ?INSN(?OP_JSGE32_IMM, Dst, 0, Off, Imm).
jsge32_reg(Dst, Src, Off)  -> ?INSN(?OP_JSGE32_REG, Dst, Src, Off, 0).
jlt32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JLT32_IMM,  Dst, 0, Off, Imm).
jlt32_reg(Dst, Src, Off)   -> ?INSN(?OP_JLT32_REG,  Dst, Src, Off, 0).
jle32_imm(Dst, Imm, Off)  -> ?INSN(?OP_JLE32_IMM,  Dst, 0, Off, Imm).
jle32_reg(Dst, Src, Off)   -> ?INSN(?OP_JLE32_REG,  Dst, Src, Off, 0).
jslt32_imm(Dst, Imm, Off) -> ?INSN(?OP_JSLT32_IMM, Dst, 0, Off, Imm).
jslt32_reg(Dst, Src, Off)  -> ?INSN(?OP_JSLT32_REG, Dst, Src, Off, 0).
jsle32_imm(Dst, Imm, Off) -> ?INSN(?OP_JSLE32_IMM, Dst, 0, Off, Imm).
jsle32_reg(Dst, Src, Off)  -> ?INSN(?OP_JSLE32_REG, Dst, Src, Off, 0).

%%% ===================================================================
%%% Endian byte-swap (imm = bit width: 16, 32, or 64)
%%% ===================================================================

be16(Dst) -> ?INSN(?OP_BE, Dst, 0, 0, 16).
be32(Dst) -> ?INSN(?OP_BE, Dst, 0, 0, 32).
be64(Dst) -> ?INSN(?OP_BE, Dst, 0, 0, 64).
le16(Dst) -> ?INSN(?OP_LE, Dst, 0, 0, 16).
le32(Dst) -> ?INSN(?OP_LE, Dst, 0, 0, 32).
le64(Dst) -> ?INSN(?OP_LE, Dst, 0, 0, 64).

%%% ===================================================================
%%% Special
%%% ===================================================================

call(HelperId) -> ?INSN(?OP_CALL, 0, 0, 0, HelperId).

exit_insn() -> ?INSN(?OP_EXIT, 0, 0, 0, 0).

%%% ===================================================================
%%% Decode — binary → tuple
%%% ===================================================================

-spec decode(binary()) -> {atom(), reg(), reg(), integer(), integer()}.

%% 16-byte LD_IMM64 variants
decode(<<?OP_LD_IMM64, SrcDst, Off:16/signed-little, ImmLo:32/signed-little,
         0, 0, 0:16/little, ImmHi:32/signed-little>>) ->
    Dst = SrcDst band 16#0F,
    Src = (SrcDst bsr 4) band 16#0F,
    Imm = (ImmHi bsl 32) bor (ImmLo band 16#FFFFFFFF),
    Op = case Src of
        ?BPF_PSEUDO_MAP_FD    -> ld_map_fd;
        ?BPF_PSEUDO_MAP_VALUE -> ld_map_value;
        0                     -> ld64_imm;
        _                     -> ld64_imm
    end,
    {Op, Dst, Src, Off, Imm};

%% Standard 8-byte instruction
decode(<<Code, SrcDst, Off:16/signed-little, Imm:32/signed-little>>) ->
    Dst = SrcDst band 16#0F,
    Src = (SrcDst bsr 4) band 16#0F,
    Op = decode_opcode(Code),
    {Op, Dst, Src, Off, Imm}.

%%% ===================================================================
%%% Assemble — list of instruction binaries → flat binary
%%% ===================================================================

-spec assemble([binary()]) -> binary().
assemble(Insns) ->
    iolist_to_binary(Insns).

%%% ===================================================================
%%% Internal: opcode → atom
%%% ===================================================================

decode_opcode(?OP_ADD64_IMM)  -> add64_imm;
decode_opcode(?OP_ADD64_REG)  -> add64_reg;
decode_opcode(?OP_SUB64_IMM)  -> sub64_imm;
decode_opcode(?OP_SUB64_REG)  -> sub64_reg;
decode_opcode(?OP_MUL64_IMM)  -> mul64_imm;
decode_opcode(?OP_MUL64_REG)  -> mul64_reg;
decode_opcode(?OP_DIV64_IMM)  -> div64_imm;
decode_opcode(?OP_DIV64_REG)  -> div64_reg;
decode_opcode(?OP_OR64_IMM)   -> or64_imm;
decode_opcode(?OP_OR64_REG)   -> or64_reg;
decode_opcode(?OP_AND64_IMM)  -> and64_imm;
decode_opcode(?OP_AND64_REG)  -> and64_reg;
decode_opcode(?OP_LSH64_IMM)  -> lsh64_imm;
decode_opcode(?OP_LSH64_REG)  -> lsh64_reg;
decode_opcode(?OP_RSH64_IMM)  -> rsh64_imm;
decode_opcode(?OP_RSH64_REG)  -> rsh64_reg;
decode_opcode(?OP_NEG64)      -> neg64;
decode_opcode(?OP_MOD64_IMM)  -> mod64_imm;
decode_opcode(?OP_MOD64_REG)  -> mod64_reg;
decode_opcode(?OP_XOR64_IMM)  -> xor64_imm;
decode_opcode(?OP_XOR64_REG)  -> xor64_reg;
decode_opcode(?OP_MOV64_IMM)  -> mov64_imm;
decode_opcode(?OP_MOV64_REG)  -> mov64_reg;
decode_opcode(?OP_ARSH64_IMM) -> arsh64_imm;
decode_opcode(?OP_ARSH64_REG) -> arsh64_reg;

decode_opcode(?OP_ADD32_IMM)  -> add32_imm;
decode_opcode(?OP_ADD32_REG)  -> add32_reg;
decode_opcode(?OP_SUB32_IMM)  -> sub32_imm;
decode_opcode(?OP_SUB32_REG)  -> sub32_reg;
decode_opcode(?OP_MUL32_IMM)  -> mul32_imm;
decode_opcode(?OP_MUL32_REG)  -> mul32_reg;
decode_opcode(?OP_DIV32_IMM)  -> div32_imm;
decode_opcode(?OP_DIV32_REG)  -> div32_reg;
decode_opcode(?OP_OR32_IMM)   -> or32_imm;
decode_opcode(?OP_OR32_REG)   -> or32_reg;
decode_opcode(?OP_AND32_IMM)  -> and32_imm;
decode_opcode(?OP_AND32_REG)  -> and32_reg;
decode_opcode(?OP_LSH32_IMM)  -> lsh32_imm;
decode_opcode(?OP_LSH32_REG)  -> lsh32_reg;
decode_opcode(?OP_RSH32_IMM)  -> rsh32_imm;
decode_opcode(?OP_RSH32_REG)  -> rsh32_reg;
decode_opcode(?OP_NEG32)      -> neg32;
decode_opcode(?OP_MOD32_IMM)  -> mod32_imm;
decode_opcode(?OP_MOD32_REG)  -> mod32_reg;
decode_opcode(?OP_XOR32_IMM)  -> xor32_imm;
decode_opcode(?OP_XOR32_REG)  -> xor32_reg;
decode_opcode(?OP_MOV32_IMM)  -> mov32_imm;
decode_opcode(?OP_MOV32_REG)  -> mov32_reg;
decode_opcode(?OP_ARSH32_IMM) -> arsh32_imm;
decode_opcode(?OP_ARSH32_REG) -> arsh32_reg;

decode_opcode(?OP_LDXW)  -> ldxw;
decode_opcode(?OP_LDXH)  -> ldxh;
decode_opcode(?OP_LDXB)  -> ldxb;
decode_opcode(?OP_LDXDW) -> ldxdw;

decode_opcode(?OP_STXW)  -> stxw;
decode_opcode(?OP_STXH)  -> stxh;
decode_opcode(?OP_STXB)  -> stxb;
decode_opcode(?OP_STXDW) -> stxdw;

decode_opcode(?OP_STW)  -> stw;
decode_opcode(?OP_STH)  -> sth;
decode_opcode(?OP_STB)  -> stb;
decode_opcode(?OP_STDW) -> stdw;

decode_opcode(?OP_JA)       -> ja;
decode_opcode(?OP_JEQ_IMM)  -> jeq_imm;
decode_opcode(?OP_JEQ_REG)  -> jeq_reg;
decode_opcode(?OP_JGT_IMM)  -> jgt_imm;
decode_opcode(?OP_JGT_REG)  -> jgt_reg;
decode_opcode(?OP_JGE_IMM)  -> jge_imm;
decode_opcode(?OP_JGE_REG)  -> jge_reg;
decode_opcode(?OP_JSET_IMM) -> jset_imm;
decode_opcode(?OP_JSET_REG) -> jset_reg;
decode_opcode(?OP_JNE_IMM)  -> jne_imm;
decode_opcode(?OP_JNE_REG)  -> jne_reg;
decode_opcode(?OP_JSGT_IMM) -> jsgt_imm;
decode_opcode(?OP_JSGT_REG) -> jsgt_reg;
decode_opcode(?OP_JSGE_IMM) -> jsge_imm;
decode_opcode(?OP_JSGE_REG) -> jsge_reg;
decode_opcode(?OP_JLT_IMM)  -> jlt_imm;
decode_opcode(?OP_JLT_REG)  -> jlt_reg;
decode_opcode(?OP_JLE_IMM)  -> jle_imm;
decode_opcode(?OP_JLE_REG)  -> jle_reg;
decode_opcode(?OP_JSLT_IMM) -> jslt_imm;
decode_opcode(?OP_JSLT_REG) -> jslt_reg;
decode_opcode(?OP_JSLE_IMM) -> jsle_imm;
decode_opcode(?OP_JSLE_REG) -> jsle_reg;
decode_opcode(?OP_BE)       -> be;
decode_opcode(?OP_LE)       -> le;

decode_opcode(?OP_CALL)     -> call;
decode_opcode(?OP_EXIT)     -> exit_insn;

decode_opcode(?OP_JEQ32_IMM)  -> jeq32_imm;
decode_opcode(?OP_JEQ32_REG)  -> jeq32_reg;
decode_opcode(?OP_JGT32_IMM)  -> jgt32_imm;
decode_opcode(?OP_JGT32_REG)  -> jgt32_reg;
decode_opcode(?OP_JGE32_IMM)  -> jge32_imm;
decode_opcode(?OP_JGE32_REG)  -> jge32_reg;
decode_opcode(?OP_JSET32_IMM) -> jset32_imm;
decode_opcode(?OP_JSET32_REG) -> jset32_reg;
decode_opcode(?OP_JNE32_IMM)  -> jne32_imm;
decode_opcode(?OP_JNE32_REG)  -> jne32_reg;
decode_opcode(?OP_JSGT32_IMM) -> jsgt32_imm;
decode_opcode(?OP_JSGT32_REG) -> jsgt32_reg;
decode_opcode(?OP_JSGE32_IMM) -> jsge32_imm;
decode_opcode(?OP_JSGE32_REG) -> jsge32_reg;
decode_opcode(?OP_JLT32_IMM)  -> jlt32_imm;
decode_opcode(?OP_JLT32_REG)  -> jlt32_reg;
decode_opcode(?OP_JLE32_IMM)  -> jle32_imm;
decode_opcode(?OP_JLE32_REG)  -> jle32_reg;
decode_opcode(?OP_JSLT32_IMM) -> jslt32_imm;
decode_opcode(?OP_JSLT32_REG) -> jslt32_reg;
decode_opcode(?OP_JSLE32_IMM) -> jsle32_imm;
decode_opcode(?OP_JSLE32_REG) -> jsle32_reg;

decode_opcode(Code) -> {unknown, Code}.

%%% ===================================================================
%%% uBPF compatibility — patch ld_map_fd → ld64_imm
%%% ===================================================================

%% @doc Rewrite BPF_PSEUDO_MAP_FD (src=1) to src=0 in all LDDW instructions.
%% uBPF is a userspace VM and rejects LDDW with src != 0.  The map fd is
%% just a plain integer index, so ld64_imm is semantically correct.
-spec patch_for_ubpf(binary()) -> binary().
patch_for_ubpf(Bytecode) ->
    patch_lddw(Bytecode, <<>>).

patch_lddw(<<16#18, SrcDst, Rest:14/binary, Tail/binary>>, Acc) ->
    Dst = SrcDst band 16#0F,
    %% Clear src field → plain ld64_imm
    patch_lddw(Tail, <<Acc/binary, 16#18, Dst, Rest/binary>>);
patch_lddw(<<Insn:8/binary, Tail/binary>>, Acc) ->
    patch_lddw(Tail, <<Acc/binary, Insn/binary>>);
patch_lddw(Remainder, Acc) ->
    %% Trailing bytes (incomplete instruction or empty)
    <<Acc/binary, Remainder/binary>>.
