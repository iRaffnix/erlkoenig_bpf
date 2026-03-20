%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(ebpf_disasm).
-moduledoc """
BPF bytecode disassembler.

Decodes BPF binary into human-readable instruction strings.
""".

-include("ebpf_vm.hrl").

-export([disassemble/1, disassemble_explained/1, format_insn/1, explain_insn/1]).

-doc "Disassemble a BPF binary into a list of {PC, Text} tuples.".
-spec disassemble(binary()) -> [{non_neg_integer(), binary()}].
disassemble(Bin) ->
    Insns = ebpf_vm_decode:decode_program(Bin),
    Size = array:size(Insns),
    disasm_loop(Insns, 0, Size, []).

disasm_loop(_Insns, PC, Size, Acc) when PC >= Size ->
    lists:reverse(Acc);
disasm_loop(Insns, PC, Size, Acc) ->
    Insn = array:get(PC, Insns),
    Text = format_insn(Insn),
    disasm_loop(Insns, PC + 1, Size, [{PC, Text} | Acc]).

-doc "Disassemble with explanations: returns [{PC, Text, Explanation}].".
-spec disassemble_explained(binary()) -> [{non_neg_integer(), binary(), map()}].
disassemble_explained(Bin) ->
    Insns = ebpf_vm_decode:decode_program(Bin),
    Size = array:size(Insns),
    disasm_expl_loop(Insns, 0, Size, []).

disasm_expl_loop(_Insns, PC, Size, Acc) when PC >= Size ->
    lists:reverse(Acc);
disasm_expl_loop(Insns, PC, Size, Acc) ->
    Insn = array:get(PC, Insns),
    Text = format_insn(Insn),
    Expl = explain_insn(Insn),
    disasm_expl_loop(Insns, PC + 1, Size, [{PC, Text, Expl} | Acc]).

-doc "Format a single decoded instruction as a human-readable binary string.".
-spec format_insn(#vm_insn{}) -> binary().

%% NOP (second half of LD_IMM64)
format_insn(#vm_insn{op = nop}) ->
    <<"nop">>;
%% EXIT
format_insn(#vm_insn{op = exit_insn}) ->
    <<"exit">>;
%% ALU64 immediate
format_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}) when
    Op =:= add64_imm;
    Op =:= sub64_imm;
    Op =:= mul64_imm;
    Op =:= div64_imm;
    Op =:= or64_imm;
    Op =:= and64_imm;
    Op =:= lsh64_imm;
    Op =:= rsh64_imm;
    Op =:= mod64_imm;
    Op =:= xor64_imm;
    Op =:= mov64_imm;
    Op =:= arsh64_imm
->
    Name = alu_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, ~s", [Name, Dst, fmt_imm(Imm)]));
%% ALU64 register
format_insn(#vm_insn{op = Op, dst = Dst, src = Src}) when
    Op =:= add64_reg;
    Op =:= sub64_reg;
    Op =:= mul64_reg;
    Op =:= div64_reg;
    Op =:= or64_reg;
    Op =:= and64_reg;
    Op =:= lsh64_reg;
    Op =:= rsh64_reg;
    Op =:= mod64_reg;
    Op =:= xor64_reg;
    Op =:= mov64_reg;
    Op =:= arsh64_reg
->
    Name = alu_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, r~B", [Name, Dst, Src]));
%% NEG
format_insn(#vm_insn{op = neg64, dst = Dst}) ->
    iolist_to_binary(io_lib:format("neg64 r~B", [Dst]));
format_insn(#vm_insn{op = neg32, dst = Dst}) ->
    iolist_to_binary(io_lib:format("neg32 r~B", [Dst]));
%% ALU32 immediate
format_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}) when
    Op =:= add32_imm;
    Op =:= sub32_imm;
    Op =:= mul32_imm;
    Op =:= div32_imm;
    Op =:= or32_imm;
    Op =:= and32_imm;
    Op =:= lsh32_imm;
    Op =:= rsh32_imm;
    Op =:= mod32_imm;
    Op =:= xor32_imm;
    Op =:= mov32_imm;
    Op =:= arsh32_imm
->
    Name = alu_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, ~s", [Name, Dst, fmt_imm(Imm)]));
%% ALU32 register
format_insn(#vm_insn{op = Op, dst = Dst, src = Src}) when
    Op =:= add32_reg;
    Op =:= sub32_reg;
    Op =:= mul32_reg;
    Op =:= div32_reg;
    Op =:= or32_reg;
    Op =:= and32_reg;
    Op =:= lsh32_reg;
    Op =:= rsh32_reg;
    Op =:= mod32_reg;
    Op =:= xor32_reg;
    Op =:= mov32_reg;
    Op =:= arsh32_reg
->
    Name = alu_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, r~B", [Name, Dst, Src]));
%% LD64_IMM / LD_MAP_FD
format_insn(#vm_insn{op = ld64_imm, dst = Dst, imm = Imm}) ->
    iolist_to_binary(io_lib:format("ld64 r~B, ~s", [Dst, fmt_imm(Imm)]));
format_insn(#vm_insn{op = ld_map_fd, dst = Dst, imm = Imm}) ->
    iolist_to_binary(io_lib:format("ld_map_fd r~B, ~B", [Dst, Imm]));
format_insn(#vm_insn{op = ld_map_value, dst = Dst, imm = Imm}) ->
    iolist_to_binary(io_lib:format("ld_map_value r~B, ~B", [Dst, Imm]));
%% Memory LDX
format_insn(#vm_insn{op = ldxb, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("ldxb r~B, [r~B~s]", [Dst, Src, fmt_off(Off)]));
format_insn(#vm_insn{op = ldxh, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("ldxh r~B, [r~B~s]", [Dst, Src, fmt_off(Off)]));
format_insn(#vm_insn{op = ldxw, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("ldxw r~B, [r~B~s]", [Dst, Src, fmt_off(Off)]));
format_insn(#vm_insn{op = ldxdw, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("ldxdw r~B, [r~B~s]", [Dst, Src, fmt_off(Off)]));
%% Memory STX
format_insn(#vm_insn{op = stxb, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("stxb [r~B~s], r~B", [Dst, fmt_off(Off), Src]));
format_insn(#vm_insn{op = stxh, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("stxh [r~B~s], r~B", [Dst, fmt_off(Off), Src]));
format_insn(#vm_insn{op = stxw, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("stxw [r~B~s], r~B", [Dst, fmt_off(Off), Src]));
format_insn(#vm_insn{op = stxdw, dst = Dst, src = Src, off = Off}) ->
    iolist_to_binary(io_lib:format("stxdw [r~B~s], r~B", [Dst, fmt_off(Off), Src]));
%% Memory ST (immediate)
format_insn(#vm_insn{op = stb, dst = Dst, off = Off, imm = Imm}) ->
    iolist_to_binary(io_lib:format("stb [r~B~s], ~s", [Dst, fmt_off(Off), fmt_imm(Imm)]));
format_insn(#vm_insn{op = sth, dst = Dst, off = Off, imm = Imm}) ->
    iolist_to_binary(io_lib:format("sth [r~B~s], ~s", [Dst, fmt_off(Off), fmt_imm(Imm)]));
format_insn(#vm_insn{op = stw, dst = Dst, off = Off, imm = Imm}) ->
    iolist_to_binary(io_lib:format("stw [r~B~s], ~s", [Dst, fmt_off(Off), fmt_imm(Imm)]));
format_insn(#vm_insn{op = stdw, dst = Dst, off = Off, imm = Imm}) ->
    iolist_to_binary(io_lib:format("stdw [r~B~s], ~s", [Dst, fmt_off(Off), fmt_imm(Imm)]));
%% JA
format_insn(#vm_insn{op = ja, off = Off}) ->
    iolist_to_binary(io_lib:format("ja ~s", [fmt_jmp_off(Off)]));
%% JMP64 conditional (immediate)
format_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}) when
    Op =:= jeq_imm;
    Op =:= jgt_imm;
    Op =:= jge_imm;
    Op =:= jset_imm;
    Op =:= jne_imm;
    Op =:= jsgt_imm;
    Op =:= jsge_imm;
    Op =:= jlt_imm;
    Op =:= jle_imm;
    Op =:= jslt_imm;
    Op =:= jsle_imm
->
    Name = jmp_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, ~s, ~s", [Name, Dst, fmt_imm(Imm), fmt_jmp_off(Off)]));
%% JMP64 conditional (register)
format_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) when
    Op =:= jeq_reg;
    Op =:= jgt_reg;
    Op =:= jge_reg;
    Op =:= jset_reg;
    Op =:= jne_reg;
    Op =:= jsgt_reg;
    Op =:= jsge_reg;
    Op =:= jlt_reg;
    Op =:= jle_reg;
    Op =:= jslt_reg;
    Op =:= jsle_reg
->
    Name = jmp_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, r~B, ~s", [Name, Dst, Src, fmt_jmp_off(Off)]));
%% JMP32 conditional (immediate)
format_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}) when
    Op =:= jeq32_imm;
    Op =:= jgt32_imm;
    Op =:= jge32_imm;
    Op =:= jset32_imm;
    Op =:= jne32_imm;
    Op =:= jsgt32_imm;
    Op =:= jsge32_imm;
    Op =:= jlt32_imm;
    Op =:= jle32_imm;
    Op =:= jslt32_imm;
    Op =:= jsle32_imm
->
    Name = jmp_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, ~s, ~s", [Name, Dst, fmt_imm(Imm), fmt_jmp_off(Off)]));
%% JMP32 conditional (register)
format_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) when
    Op =:= jeq32_reg;
    Op =:= jgt32_reg;
    Op =:= jge32_reg;
    Op =:= jset32_reg;
    Op =:= jne32_reg;
    Op =:= jsgt32_reg;
    Op =:= jsge32_reg;
    Op =:= jlt32_reg;
    Op =:= jle32_reg;
    Op =:= jslt32_reg;
    Op =:= jsle32_reg
->
    Name = jmp_name(Op),
    iolist_to_binary(io_lib:format("~s r~B, r~B, ~s", [Name, Dst, Src, fmt_jmp_off(Off)]));
%% Endian
format_insn(#vm_insn{op = be, dst = Dst, imm = Width}) ->
    iolist_to_binary(io_lib:format("be~B r~B", [Width, Dst]));
format_insn(#vm_insn{op = le, dst = Dst, imm = Width}) ->
    iolist_to_binary(io_lib:format("le~B r~B", [Width, Dst]));
%% CALL
format_insn(#vm_insn{op = call, imm = Id}) ->
    Name = helper_name(Id),
    iolist_to_binary(io_lib:format("call ~s", [Name]));
%% Unknown
format_insn(#vm_insn{op = {unknown, Code}}) ->
    iolist_to_binary(io_lib:format("unknown 0x~2.16.0B", [Code]));
format_insn(#vm_insn{op = Op}) ->
    iolist_to_binary(io_lib:format("~p", [Op])).

%%% ===================================================================
%%% Internal formatting helpers
%%% ===================================================================

fmt_imm(Imm) when Imm >= 0, Imm =< 255 ->
    io_lib:format("~B", [Imm]);
fmt_imm(Imm) when Imm >= 0 ->
    io_lib:format("0x~.16B", [Imm]);
fmt_imm(Imm) ->
    io_lib:format("-0x~.16B", [-Imm]).

fmt_off(0) -> "";
fmt_off(Off) when Off >= 0 -> io_lib:format("+~B", [Off]);
fmt_off(Off) -> io_lib:format("~B", [Off]).

fmt_jmp_off(Off) when Off >= 0 -> io_lib:format("+~B", [Off]);
fmt_jmp_off(Off) -> io_lib:format("~B", [Off]).

alu_name(add64_imm) -> "add64";
alu_name(add64_reg) -> "add64";
alu_name(sub64_imm) -> "sub64";
alu_name(sub64_reg) -> "sub64";
alu_name(mul64_imm) -> "mul64";
alu_name(mul64_reg) -> "mul64";
alu_name(div64_imm) -> "div64";
alu_name(div64_reg) -> "div64";
alu_name(or64_imm) -> "or64";
alu_name(or64_reg) -> "or64";
alu_name(and64_imm) -> "and64";
alu_name(and64_reg) -> "and64";
alu_name(lsh64_imm) -> "lsh64";
alu_name(lsh64_reg) -> "lsh64";
alu_name(rsh64_imm) -> "rsh64";
alu_name(rsh64_reg) -> "rsh64";
alu_name(mod64_imm) -> "mod64";
alu_name(mod64_reg) -> "mod64";
alu_name(xor64_imm) -> "xor64";
alu_name(xor64_reg) -> "xor64";
alu_name(mov64_imm) -> "mov64";
alu_name(mov64_reg) -> "mov64";
alu_name(arsh64_imm) -> "arsh64";
alu_name(arsh64_reg) -> "arsh64";
alu_name(add32_imm) -> "add32";
alu_name(add32_reg) -> "add32";
alu_name(sub32_imm) -> "sub32";
alu_name(sub32_reg) -> "sub32";
alu_name(mul32_imm) -> "mul32";
alu_name(mul32_reg) -> "mul32";
alu_name(div32_imm) -> "div32";
alu_name(div32_reg) -> "div32";
alu_name(or32_imm) -> "or32";
alu_name(or32_reg) -> "or32";
alu_name(and32_imm) -> "and32";
alu_name(and32_reg) -> "and32";
alu_name(lsh32_imm) -> "lsh32";
alu_name(lsh32_reg) -> "lsh32";
alu_name(rsh32_imm) -> "rsh32";
alu_name(rsh32_reg) -> "rsh32";
alu_name(mod32_imm) -> "mod32";
alu_name(mod32_reg) -> "mod32";
alu_name(xor32_imm) -> "xor32";
alu_name(xor32_reg) -> "xor32";
alu_name(mov32_imm) -> "mov32";
alu_name(mov32_reg) -> "mov32";
alu_name(arsh32_imm) -> "arsh32";
alu_name(arsh32_reg) -> "arsh32".

jmp_name(jeq_imm) -> "jeq";
jmp_name(jeq_reg) -> "jeq";
jmp_name(jgt_imm) -> "jgt";
jmp_name(jgt_reg) -> "jgt";
jmp_name(jge_imm) -> "jge";
jmp_name(jge_reg) -> "jge";
jmp_name(jset_imm) -> "jset";
jmp_name(jset_reg) -> "jset";
jmp_name(jne_imm) -> "jne";
jmp_name(jne_reg) -> "jne";
jmp_name(jsgt_imm) -> "jsgt";
jmp_name(jsgt_reg) -> "jsgt";
jmp_name(jsge_imm) -> "jsge";
jmp_name(jsge_reg) -> "jsge";
jmp_name(jlt_imm) -> "jlt";
jmp_name(jlt_reg) -> "jlt";
jmp_name(jle_imm) -> "jle";
jmp_name(jle_reg) -> "jle";
jmp_name(jslt_imm) -> "jslt";
jmp_name(jslt_reg) -> "jslt";
jmp_name(jsle_imm) -> "jsle";
jmp_name(jsle_reg) -> "jsle";
jmp_name(jeq32_imm) -> "jeq32";
jmp_name(jeq32_reg) -> "jeq32";
jmp_name(jgt32_imm) -> "jgt32";
jmp_name(jgt32_reg) -> "jgt32";
jmp_name(jge32_imm) -> "jge32";
jmp_name(jge32_reg) -> "jge32";
jmp_name(jset32_imm) -> "jset32";
jmp_name(jset32_reg) -> "jset32";
jmp_name(jne32_imm) -> "jne32";
jmp_name(jne32_reg) -> "jne32";
jmp_name(jsgt32_imm) -> "jsgt32";
jmp_name(jsgt32_reg) -> "jsgt32";
jmp_name(jsge32_imm) -> "jsge32";
jmp_name(jsge32_reg) -> "jsge32";
jmp_name(jlt32_imm) -> "jlt32";
jmp_name(jlt32_reg) -> "jlt32";
jmp_name(jle32_imm) -> "jle32";
jmp_name(jle32_reg) -> "jle32";
jmp_name(jslt32_imm) -> "jslt32";
jmp_name(jslt32_reg) -> "jslt32";
jmp_name(jsle32_imm) -> "jsle32";
jmp_name(jsle32_reg) -> "jsle32".

helper_name(1) -> "map_lookup_elem";
helper_name(2) -> "map_update_elem";
helper_name(3) -> "map_delete_elem";
helper_name(5) -> "ktime_get_ns";
helper_name(6) -> "trace_printk";
helper_name(14) -> "get_smp_processor_id";
helper_name(23) -> "redirect";
helper_name(26) -> "skb_load_bytes";
helper_name(130) -> "ringbuf_output";
helper_name(Id) -> io_lib:format("#~B", [Id]).

%%% ===================================================================
%%% Instruction explanation  - human-readable description of what
%%% each BPF instruction does, for educational display.
%%% ===================================================================

-doc "Generate a human-readable explanation of a decoded BPF instruction. Returns a map with 'short' (one-line summary) and 'detail' (full explanation).".
-spec explain_insn(#vm_insn{}) ->
    #{
        short := binary(),
        detail := binary(),
        category := <<_:32, _:_*8>>
    }.

explain_insn(#vm_insn{op = nop}) ->
    #{
        short => <<"No operation">>,
        detail => <<
            "Second half of a 16-byte LD_IMM64 instruction. "
            "The BPF ISA uses two 8-byte slots for 64-bit immediate loads. "
            "This NOP is the placeholder for the upper 32 bits."
        >>,
        category => <<"system">>
    };
explain_insn(#vm_insn{op = exit_insn}) ->
    #{
        short => <<"Program exit  - return R0 to caller">>,
        detail => <<
            "Terminates the BPF program. The value in R0 is returned "
            "as the program result. For XDP programs: "
            "0=ABORTED, 1=DROP, 2=PASS, 3=TX, 4=REDIRECT."
        >>,
        category => <<"control">>
    };
%% MOV
explain_insn(#vm_insn{op = mov64_imm, dst = Dst, imm = Imm}) ->
    #{
        short => fmt("Set r~B to ~s", [Dst, explain_value(Imm)]),
        detail => fmt(
            "Load a 32-bit immediate value into a 64-bit register. "
            "mov64_imm is the most common way to initialize registers "
            "with constants (action codes, offsets, sizes).",
            []
        ),
        category => <<"data movement">>
    };
explain_insn(#vm_insn{op = mov64_reg, dst = Dst, src = Src}) ->
    #{
        short => fmt("Copy r~B into r~B", [Src, Dst]),
        detail => fmt(
            "Register-to-register move (64-bit). Copies the full "
            "64-bit value. ~s",
            [explain_reg_role(Dst, Src)]
        ),
        category => <<"data movement">>
    };
explain_insn(#vm_insn{op = mov32_imm, dst = Dst, imm = Imm}) ->
    #{
        short => fmt("Set lower 32 bits of r~B to ~B, zero upper 32", [Dst, Imm]),
        detail => <<
            "32-bit move clears the upper 32 bits of the destination register. "
            "This is the BPF zero-extension rule  - all 32-bit operations "
            "automatically zero-extend to 64 bits."
        >>,
        category => <<"data movement">>
    };
explain_insn(#vm_insn{op = mov32_reg, dst = Dst, src = Src}) ->
    #{
        short => fmt("Copy lower 32 bits of r~B into r~B, zero upper 32", [Src, Dst]),
        detail => <<
            "32-bit register move with automatic zero-extension. "
            "The upper 32 bits of the destination are set to zero."
        >>,
        category => <<"data movement">>
    };
%% LD64
explain_insn(#vm_insn{op = ld64_imm, dst = Dst, imm = Imm}) ->
    #{
        short => fmt("Load 64-bit immediate ~s into r~B", [explain_value(Imm), Dst]),
        detail => <<
            "LD_IMM64 is the only BPF instruction that spans 16 bytes "
            "(two instruction slots). It loads a full 64-bit constant. "
            "Used for large values that don't fit in a 32-bit immediate."
        >>,
        category => <<"data movement">>
    };
explain_insn(#vm_insn{op = ld_map_fd, dst = Dst, imm = Fd}) ->
    #{
        short => fmt("Load map descriptor ~B into r~B", [Fd, Dst]),
        detail => fmt(
            "Loads a BPF map file descriptor (fd=~B) into a register. "
            "In the kernel, this is resolved to a map pointer by the verifier. "
            "In our VM, the fd is a map index used by helper calls "
            "(map_lookup_elem, map_update_elem).",
            [Fd]
        ),
        category => <<"maps">>
    };
%% ALU64
explain_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}) when
    Op =:= add64_imm;
    Op =:= sub64_imm;
    Op =:= mul64_imm;
    Op =:= div64_imm;
    Op =:= mod64_imm;
    Op =:= and64_imm;
    Op =:= or64_imm;
    Op =:= xor64_imm;
    Op =:= lsh64_imm;
    Op =:= rsh64_imm;
    Op =:= arsh64_imm
->
    {OpName, OpDesc} = explain_alu(Op),
    #{
        short => fmt("r~B ~s ~s (64-bit)", [Dst, OpName, explain_value(Imm)]),
        detail => fmt(
            "~s Uses 64-bit arithmetic (full register width). "
            "Result is stored back in r~B.",
            [OpDesc, Dst]
        ),
        category => <<"arithmetic">>
    };
explain_insn(#vm_insn{op = Op, dst = Dst, src = Src}) when
    Op =:= add64_reg;
    Op =:= sub64_reg;
    Op =:= mul64_reg;
    Op =:= div64_reg;
    Op =:= mod64_reg;
    Op =:= and64_reg;
    Op =:= or64_reg;
    Op =:= xor64_reg;
    Op =:= lsh64_reg;
    Op =:= rsh64_reg;
    Op =:= arsh64_reg
->
    {OpName, OpDesc} = explain_alu(Op),
    #{
        short => fmt("r~B ~s r~B (64-bit)", [Dst, OpName, Src]),
        detail => fmt(
            "~s Uses 64-bit arithmetic. "
            "Result is stored back in r~B.",
            [OpDesc, Dst]
        ),
        category => <<"arithmetic">>
    };
explain_insn(#vm_insn{op = neg64, dst = Dst}) ->
    #{
        short => fmt("Negate r~B (two's complement, 64-bit)", [Dst]),
        detail => <<
            "Two's complement negation: r = -r. Equivalent to 0 - r. "
            "Operates on the full 64-bit register width."
        >>,
        category => <<"arithmetic">>
    };
%% ALU32
explain_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}) when
    Op =:= add32_imm;
    Op =:= sub32_imm;
    Op =:= mul32_imm;
    Op =:= div32_imm;
    Op =:= mod32_imm;
    Op =:= and32_imm;
    Op =:= or32_imm;
    Op =:= xor32_imm;
    Op =:= lsh32_imm;
    Op =:= rsh32_imm;
    Op =:= arsh32_imm
->
    {OpName, OpDesc} = explain_alu(Op),
    #{
        short => fmt("r~B ~s ~s (32-bit, zero-extends)", [Dst, OpName, explain_value(Imm)]),
        detail => fmt(
            "~s 32-bit operation: uses only the lower 32 bits, then "
            "zero-extends the result to 64 bits (BPF rule).",
            [OpDesc]
        ),
        category => <<"arithmetic">>
    };
explain_insn(#vm_insn{op = Op, dst = Dst, src = Src}) when
    Op =:= add32_reg;
    Op =:= sub32_reg;
    Op =:= mul32_reg;
    Op =:= div32_reg;
    Op =:= mod32_reg;
    Op =:= and32_reg;
    Op =:= or32_reg;
    Op =:= xor32_reg;
    Op =:= lsh32_reg;
    Op =:= rsh32_reg;
    Op =:= arsh32_reg
->
    {OpName, OpDesc} = explain_alu(Op),
    #{
        short => fmt("r~B ~s r~B (32-bit, zero-extends)", [Dst, OpName, Src]),
        detail => fmt("~s 32-bit register operation with zero-extension.", [OpDesc]),
        category => <<"arithmetic">>
    };
explain_insn(#vm_insn{op = neg32, dst = Dst}) ->
    #{
        short => fmt("Negate lower 32 bits of r~B, zero upper 32", [Dst]),
        detail => <<"32-bit two's complement negation with zero-extension.">>,
        category => <<"arithmetic">>
    };
%% Memory LDX
explain_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) when
    Op =:= ldxb; Op =:= ldxh; Op =:= ldxw; Op =:= ldxdw
->
    {Size, SizeName} = ldx_size(Op),
    Region = explain_memory_region(Src, Off),
    #{
        short => fmt(
            "Load ~s from memory [r~B~s] into r~B",
            [SizeName, Src, fmt_off_str(Off), Dst]
        ),
        detail => fmt(
            "Read ~B byte(s) from address (r~B + ~B). ~s "
            "The value is zero-extended to 64 bits. "
            "This is a LOAD operation  - memory to register.",
            [Size, Src, Off, Region]
        ),
        category => <<"memory">>
    };
%% Memory STX
explain_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) when
    Op =:= stxb; Op =:= stxh; Op =:= stxw; Op =:= stxdw
->
    {Size, SizeName} = stx_size(Op),
    Region = explain_memory_region(Dst, Off),
    #{
        short => fmt(
            "Store ~s from r~B into memory [r~B~s]",
            [SizeName, Src, Dst, fmt_off_str(Off)]
        ),
        detail => fmt(
            "Write ~B byte(s) from register r~B to address (r~B + ~B). ~s "
            "This is a STORE operation  - register to memory.",
            [Size, Src, Dst, Off, Region]
        ),
        category => <<"memory">>
    };
%% Memory ST (immediate)
explain_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}) when
    Op =:= stb; Op =:= sth; Op =:= stw; Op =:= stdw
->
    {Size, SizeName} = st_size(Op),
    #{
        short => fmt(
            "Store immediate ~s (~s) to [r~B~s]",
            [SizeName, explain_value(Imm), Dst, fmt_off_str(Off)]
        ),
        detail => fmt(
            "Write ~B byte(s) of the immediate value ~B to memory at "
            "(r~B + ~B). Used for initializing stack memory or map keys/values "
            "with constants.",
            [Size, Imm, Dst, Off]
        ),
        category => <<"memory">>
    };
%% JA
explain_insn(#vm_insn{op = ja, off = Off}) ->
    Target = Off + 1,
    #{
        short => fmt("Unconditional jump ~s~B instructions", [sign(Off), abs(Off)]),
        detail => fmt(
            "Jump forward/backward by ~B instruction(s) (to PC+~B). "
            "Unconditional jumps implement 'else' branches and loop back-edges. "
            "The offset is relative to the NEXT instruction (PC+1).",
            [abs(Off), Target]
        ),
        category => <<"control flow">>
    };
%% JMP conditional (immediate)
explain_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}) when
    Op =:= jeq_imm;
    Op =:= jgt_imm;
    Op =:= jge_imm;
    Op =:= jset_imm;
    Op =:= jne_imm;
    Op =:= jsgt_imm;
    Op =:= jsge_imm;
    Op =:= jlt_imm;
    Op =:= jle_imm;
    Op =:= jslt_imm;
    Op =:= jsle_imm;
    Op =:= jeq32_imm;
    Op =:= jgt32_imm;
    Op =:= jge32_imm;
    Op =:= jset32_imm;
    Op =:= jne32_imm;
    Op =:= jsgt32_imm;
    Op =:= jsge32_imm;
    Op =:= jlt32_imm;
    Op =:= jle32_imm;
    Op =:= jslt32_imm;
    Op =:= jsle32_imm
->
    {CmpStr, CmpDesc, Signed} = explain_jmp(Op),
    Width =
        case is_jmp32(Op) of
            true -> <<"32-bit">>;
            false -> <<"64-bit">>
        end,
    #{
        short => fmt("If r~B ~s ~s, jump ~s~B", [
            Dst, CmpStr, explain_value(Imm), sign(Off), abs(Off)
        ]),
        detail => fmt(
            "Conditional branch: compare r~B ~s ~B (~s, ~s). "
            "If TRUE, jump by ~B (to PC+~B). If FALSE, fall through to next instruction. "
            "~s",
            [Dst, CmpDesc, Imm, Width, Signed, Off, Off + 1, explain_jmp_context(Op)]
        ),
        category => <<"control flow">>
    };
%% JMP conditional (register)
explain_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) when
    Op =:= jeq_reg;
    Op =:= jgt_reg;
    Op =:= jge_reg;
    Op =:= jset_reg;
    Op =:= jne_reg;
    Op =:= jsgt_reg;
    Op =:= jsge_reg;
    Op =:= jlt_reg;
    Op =:= jle_reg;
    Op =:= jslt_reg;
    Op =:= jsle_reg;
    Op =:= jeq32_reg;
    Op =:= jgt32_reg;
    Op =:= jge32_reg;
    Op =:= jset32_reg;
    Op =:= jne32_reg;
    Op =:= jsgt32_reg;
    Op =:= jsge32_reg;
    Op =:= jlt32_reg;
    Op =:= jle32_reg;
    Op =:= jslt32_reg;
    Op =:= jsle32_reg
->
    {CmpStr, CmpDesc, Signed} = explain_jmp(Op),
    Width =
        case is_jmp32(Op) of
            true -> <<"32-bit">>;
            false -> <<"64-bit">>
        end,
    #{
        short => fmt("If r~B ~s r~B, jump ~s~B", [Dst, CmpStr, Src, sign(Off), abs(Off)]),
        detail => fmt(
            "Conditional branch: compare r~B ~s r~B (~s, ~s). "
            "TRUE => jump by ~B. FALSE => fall through.",
            [Dst, CmpDesc, Src, Width, Signed, Off]
        ),
        category => <<"control flow">>
    };
%% Endian
explain_insn(#vm_insn{op = be, dst = Dst, imm = Width}) ->
    #{
        short => fmt("Byte-swap r~B to big-endian (~B-bit)", [Dst, Width]),
        detail => fmt(
            "Convert the lowest ~B bits of r~B from host byte order "
            "(little-endian on x86) to network byte order (big-endian). "
            "Essential for comparing packet fields  - network protocols "
            "use big-endian.",
            [Width, Dst]
        ),
        category => <<"endian">>
    };
explain_insn(#vm_insn{op = le, dst = Dst, imm = Width}) ->
    #{
        short => fmt("Convert r~B to little-endian (~B-bit)", [Dst, Width]),
        detail => fmt(
            "On little-endian hosts (x86, ARM), this is a no-op that "
            "just masks r~B to ~B bits. On big-endian hosts, it would "
            "byte-swap.",
            [Dst, Width]
        ),
        category => <<"endian">>
    };
%% CALL
explain_insn(#vm_insn{op = call, imm = Id}) ->
    {Name, HDesc} = explain_helper(Id),
    #{
        short => fmt("Call helper: ~s", [Name]),
        detail => fmt(
            "BPF helper call #~B (~s). ~s "
            "Arguments are passed in R1-R5, result returned in R0. "
            "Caller-saved registers (R1-R5) are destroyed after the call.",
            [Id, Name, HDesc]
        ),
        category => <<"helper call">>
    };
%% Unknown / fallback
explain_insn(#vm_insn{op = Op}) ->
    #{
        short => fmt("~p", [Op]),
        detail => <<"Unknown or unhandled instruction opcode.">>,
        category => <<"unknown">>
    }.

%%% ===================================================================
%%% Explanation helpers
%%% ===================================================================

fmt(Format, Args) ->
    iolist_to_binary(io_lib:format(Format, Args)).

sign(N) when N >= 0 -> <<"+">>;
sign(_) -> <<"-">>.

explain_value(0) -> <<"0">>;
explain_value(1) -> <<"1 (XDP_DROP)">>;
explain_value(2) -> <<"2 (XDP_PASS)">>;
explain_value(V) when V >= 0, V =< 255 -> integer_to_binary(V);
explain_value(V) when V =:= 16#0800 -> <<"0x0800 (IPv4 EtherType)">>;
explain_value(V) when V =:= 16#0806 -> <<"0x0806 (ARP EtherType)">>;
explain_value(V) when V =:= 16#86DD -> <<"0x86DD (IPv6 EtherType)">>;
explain_value(V) when V >= 0 -> fmt("0x~.16B", [V]);
explain_value(V) -> fmt("~B", [V]).

explain_reg_role(6, 1) ->
    <<
        "Common pattern: save context pointer (R1) to callee-saved R6. "
        "R1 would be destroyed by helper calls, but R6 survives."
    >>;
explain_reg_role(0, Src) ->
    fmt("Sets return register R0 from r~B  - preparing program exit value.", [Src]);
explain_reg_role(_, _) ->
    <<>>.

explain_memory_region(6, Off) when Off >= 0, Off =< 16 ->
    fmt(
        "R6 typically holds the XDP context pointer (xdp_md). "
        "Offset ~B accesses: ~s.",
        [Off, explain_ctx_field(Off)]
    );
explain_memory_region(10, Off) when Off < 0 ->
    fmt(
        "R10 is the frame pointer (stack base). "
        "Negative offset ~B = stack slot used for local variables, "
        "map keys, or spilled registers.",
        [Off]
    );
explain_memory_region(_, _) ->
    <<>>.

explain_ctx_field(0) -> <<"data (packet start pointer)">>;
explain_ctx_field(4) -> <<"data_end (packet end pointer)">>;
explain_ctx_field(8) -> <<"data_meta (metadata area pointer)">>;
explain_ctx_field(12) -> <<"ingress_ifindex">>;
explain_ctx_field(16) -> <<"rx_queue_index">>;
explain_ctx_field(_) -> <<"(context field)">>.

ldx_size(ldxb) -> {1, <<"1 byte">>};
ldx_size(ldxh) -> {2, <<"2 bytes (half-word)">>};
ldx_size(ldxw) -> {4, <<"4 bytes (word)">>};
ldx_size(ldxdw) -> {8, <<"8 bytes (double-word)">>}.

stx_size(stxb) -> {1, <<"1 byte">>};
stx_size(stxh) -> {2, <<"2 bytes">>};
stx_size(stxw) -> {4, <<"4 bytes">>};
stx_size(stxdw) -> {8, <<"8 bytes">>}.

st_size(stb) -> {1, <<"1 byte">>};
st_size(sth) -> {2, <<"2 bytes">>};
st_size(stw) -> {4, <<"4 bytes">>};
st_size(stdw) -> {8, <<"8 bytes">>}.

fmt_off_str(0) -> <<"">>;
fmt_off_str(Off) when Off >= 0 -> fmt("+~B", [Off]);
fmt_off_str(Off) -> fmt("~B", [Off]).

explain_alu(Op) ->
    Base = strip_alu_suffix(Op),
    case Base of
        add ->
            {<<"+">>, <<"Addition: dst = dst + src/imm.">>};
        sub ->
            {<<"-">>, <<"Subtraction: dst = dst - src/imm.">>};
        mul ->
            {<<"*">>, <<"Multiplication: dst = dst * src/imm.">>};
        'div' ->
            {<<"/">>,
                <<"Unsigned division: dst = dst / src/imm. Division by zero returns 0 in BPF.">>};
        mod ->
            {<<"%">>, <<"Unsigned modulo: dst = dst %% src/imm.">>};
        and_op ->
            {<<"&">>, <<"Bitwise AND. Used for masking bits (e.g., extracting TCP flags).">>};
        or_op ->
            {<<"|">>, <<"Bitwise OR. Used for combining flags.">>};
        xor_op ->
            {<<"^">>, <<"Bitwise XOR. Used for flipping bits or simple hashing.">>};
        lsh ->
            {<<"<<">>, <<"Logical left shift: dst = dst << src/imm. Multiplies by powers of 2.">>};
        rsh ->
            {<<">>">>, <<"Logical right shift (unsigned): fills upper bits with zeros.">>};
        arsh ->
            {<<">>>">>, <<"Arithmetic right shift (signed): preserves the sign bit.">>};
        mov ->
            {<<"=">>, <<"Move/assign value.">>};
        _ ->
            {fmt("~p", [Base]), fmt("ALU operation: ~p.", [Base])}
    end.

strip_alu_suffix(Op) ->
    S = atom_to_list(Op),
    Stripped = lists:foldl(
        fun(Suffix, Acc) ->
            case lists:suffix(Suffix, Acc) andalso length(Acc) > length(Suffix) of
                true -> lists:sublist(Acc, length(Acc) - length(Suffix));
                false -> Acc
            end
        end,
        S,
        ["64_imm", "64_reg", "32_imm", "32_reg"]
    ),
    %% Map back to atoms  - 'and', 'or', 'xor' are reserved words or don't exist
    %% as atoms in the VM, so we use explicit mapping for bitwise ops.
    case Stripped of
        "and" -> and_op;
        "or" -> or_op;
        "xor" -> xor_op;
        _ -> list_to_existing_atom(Stripped)
    end.

explain_jmp(Op) ->
    Base = strip_jmp_suffix(Op),
    case Base of
        jeq -> {<<"==">>, <<"equals">>, <<"unsigned">>};
        jne -> {<<"!=">>, <<"not equals">>, <<"unsigned">>};
        jgt -> {<<">">>, <<"greater than">>, <<"unsigned">>};
        jge -> {<<">=">>, <<"greater or equal">>, <<"unsigned">>};
        jlt -> {<<"<">>, <<"less than">>, <<"unsigned">>};
        jle -> {<<"<=">>, <<"less or equal">>, <<"unsigned">>};
        jset -> {<<"&">>, <<"bitwise AND non-zero">>, <<"unsigned">>};
        jsgt -> {<<">">>, <<"greater than">>, <<"signed">>};
        jsge -> {<<">=">>, <<"greater or equal">>, <<"signed">>};
        jslt -> {<<"<">>, <<"less than">>, <<"signed">>};
        jsle -> {<<"<=">>, <<"less or equal">>, <<"signed">>};
        _ -> {fmt("~p", [Base]), fmt("~p", [Base]), <<"unknown">>}
    end.

strip_jmp_suffix(Op) ->
    S = atom_to_list(Op),
    Stripped = lists:foldl(
        fun(Suffix, Acc) ->
            case lists:suffix(Suffix, Acc) andalso length(Acc) > length(Suffix) of
                true -> lists:sublist(Acc, length(Acc) - length(Suffix));
                false -> Acc
            end
        end,
        S,
        ["32_imm", "32_reg", "_imm", "_reg"]
    ),
    list_to_existing_atom(Stripped).

is_jmp32(Op) ->
    S = atom_to_list(Op),
    lists:suffix("32_imm", S) orelse lists:suffix("32_reg", S).

explain_jmp_context(Op) ->
    case strip_jmp_suffix(Op) of
        jne ->
            <<
                "JNE is the compiler's go-to for 'if x != y'  - often used for "
                "protocol checks (ethertype, IP protocol, TCP flags)."
            >>;
        jle ->
            <<
                "JLE is commonly used for bounds checks: "
                "'if data + N <= data_end' ensures packet access is safe."
            >>;
        jgt ->
            <<
                "JGT often implements threshold checks: "
                "'if count > limit then DROP'."
            >>;
        jeq ->
            <<
                "JEQ tests exact equality  - used for matching specific "
                "protocol values, ports, or flag patterns."
            >>;
        _ ->
            <<>>
    end.

explain_helper(1) ->
    {<<"map_lookup_elem">>, <<
        "Look up a key in a BPF map. R1=map_fd, R2=key_ptr. "
        "Returns a pointer to the value in R0, or NULL (0) if not found. "
        "You MUST null-check the result before dereferencing."
    >>};
explain_helper(2) ->
    {<<"map_update_elem">>, <<
        "Insert or update a key/value pair in a BPF map. "
        "R1=map_fd, R2=key_ptr, R3=value_ptr, R4=flags. "
        "Returns 0 on success."
    >>};
explain_helper(3) ->
    {<<"map_delete_elem">>, <<
        "Delete a key from a BPF map. R1=map_fd, R2=key_ptr. "
        "Returns 0 on success, negative on error."
    >>};
explain_helper(5) ->
    {<<"ktime_get_ns">>, <<
        "Get current kernel time in nanoseconds. No arguments. "
        "Used for rate limiting and time-based decisions."
    >>};
explain_helper(6) ->
    {<<"trace_printk">>, <<
        "Print to the kernel trace pipe (debugging). "
        "Format string in R1, args in R2-R5."
    >>};
explain_helper(Id) ->
    {iolist_to_binary(helper_name(Id)), fmt("BPF helper function #~B.", [Id])}.
