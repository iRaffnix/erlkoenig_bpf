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

-module(ebpf_vm).
-moduledoc """
Pure Erlang BPF virtual machine.

Executes BPF bytecode without kernel interaction, suitable for
testing, simulation, and cross-validation.

Usage:
  Prog = ebpf_insn:assemble([ebpf_insn:mov64_imm(0, 42), ebpf_insn:exit_insn()]),
  {ok, 42} = ebpf_vm:run(Prog, #{}).
""".

-include("ebpf_vm.hrl").

-export([run/2, run/3, run_stateful/4, create_maps/1, destroy_maps/1]).

-define(MASK64, 16#FFFFFFFFFFFFFFFF).
-define(MASK32, 16#FFFFFFFF).

-doc "Run a BPF program with context.".
run(ProgBin, Ctx) ->
    run(ProgBin, Ctx, #{}).
run(ProgBin, Ctx, Opts) ->
    {_MapsFds, MapsTabs, MapsMeta} = setup_maps(maps:get(maps, Opts, [])),
    try
        run_with_maps(ProgBin, Ctx, MapsTabs, MapsMeta, Opts)
    after
        destroy_maps({MapsTabs, MapsMeta})
    end.

-doc """
Run a BPF program with pre-existing maps.
Returns {ok, RetVal, {MapsTabs, MapsMeta}} so maps survive across runs.
Create maps with create_maps/1, destroy with destroy_maps/1.
""".
-spec run_stateful(
    binary(),
    map(),
    {#{non_neg_integer() => ets:tid()}, #{non_neg_integer() => #map_meta{}}},
    map()
) ->
    {ok, non_neg_integer(),
        {#{non_neg_integer() => ets:tid()}, #{non_neg_integer() => #map_meta{}}}}
    | {error, term()}.
run_stateful(ProgBin, Ctx, {MapsTabs, MapsMeta}, Opts) ->
    case run_with_maps(ProgBin, Ctx, MapsTabs, MapsMeta, Opts) of
        {ok, RetVal} -> {ok, RetVal, {MapsTabs, MapsMeta}};
        {error, _} = Err -> Err
    end.

-doc "Create maps from specs, for use with run_stateful/4.".
-spec create_maps([{atom(), pos_integer(), pos_integer(), pos_integer()}]) ->
    {#{non_neg_integer() => ets:tid()}, #{non_neg_integer() => #map_meta{}}}.
create_maps(MapSpecs) ->
    {_, _, TabAcc, MetaAcc} = lists:foldl(
        fun({Type, KS, VS, Max}, {Idx, _FdAcc, TAcc, MAcc}) ->
            {_Fd, Tab, Meta} = ebpf_vm_maps:create(Type, KS, VS, Max),
            {Idx + 1, #{}, TAcc#{Idx => Tab}, MAcc#{Idx => Meta}}
        end,
        {0, #{}, #{}, #{}},
        MapSpecs
    ),
    {TabAcc, MetaAcc}.

-doc "Destroy maps created by create_maps/1.".
-spec destroy_maps({#{non_neg_integer() => ets:tid()}, #{non_neg_integer() => #map_meta{}}}) -> ok.
destroy_maps({MapsTabs, _MapsMeta}) ->
    maps:foreach(fun(_, Tab) -> ebpf_vm_maps:destroy(Tab) end, MapsTabs),
    ok.

run_with_maps(ProgBin, Ctx, MapsTabs, MapsMeta, Opts) ->
    Insns = ebpf_vm_decode:decode_program(ProgBin),
    InsnCount = array:size(Insns),
    StackTop = ?VM_STACK_BASE + ?VM_STACK_SIZE,
    CtxPtr = ?VM_CTX_BASE,
    InitRegs = #{
        0 => 0,
        1 => CtxPtr,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => StackTop
    },
    St = #vm_state{
        regs = InitRegs,
        pc = 0,
        stack = <<0:(?VM_STACK_SIZE * 8)>>,
        insns = Insns,
        insn_count = InsnCount,
        memory = #{
            ctx => maps:get(ctx, Ctx, <<>>),
            packet => maps:get(packet, Ctx, <<>>)
        },
        maps = MapsTabs,
        map_meta = MapsMeta,
        insn_limit = maps:get(insn_limit, Opts, 1000000),
        trace = maps:get(trace, Opts, false)
    },
    exec_loop(St).

exec_loop(#vm_state{pc = PC, insn_count = Count}) when PC >= Count ->
    {error, {pc_oob, PC}};
exec_loop(#vm_state{insn_executed = N, insn_limit = Limit}) when N >= Limit ->
    {error, insn_limit_exceeded};
exec_loop(#vm_state{pc = PC, insns = Insns} = St) ->
    Insn = array:get(PC, Insns),
    St2 = St#vm_state{insn_executed = St#vm_state.insn_executed + 1},
    exec_insn(Insn, St2).

%% === EXIT ===
exec_insn(#vm_insn{op = exit_insn}, #vm_state{regs = Regs}) ->
    R0 = maps:get(0, Regs, 0),
    {ok, R0};
%% === NOP (second half of LD_IMM64) ===
exec_insn(#vm_insn{op = nop}, St) ->
    exec_loop(St#vm_state{pc = St#vm_state.pc + 1});
%% === ALU64 immediate ===
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, St) when
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
    AluOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, Imm band ?MASK64, 64),
    exec_loop(set_reg(advance(St), Dst, Result));
exec_insn(#vm_insn{op = neg64, dst = Dst}, St) ->
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(neg, DstVal, 0, 64),
    exec_loop(set_reg(advance(St), Dst, Result));
%% === ALU64 register ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src}, St) when
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
    AluOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, SrcVal, 64),
    exec_loop(set_reg(advance(St), Dst, Result));
%% === ALU32 immediate ===
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, St) when
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
    AluOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, Imm band ?MASK32, 32),
    exec_loop(set_reg(advance(St), Dst, Result));
exec_insn(#vm_insn{op = neg32, dst = Dst}, St) ->
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(neg, DstVal, 0, 32),
    exec_loop(set_reg(advance(St), Dst, Result));
%% === ALU32 register ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src}, St) when
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
    AluOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, SrcVal, 32),
    exec_loop(set_reg(advance(St), Dst, Result));
%% === LD64_IMM / LD_MAP_FD ===
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, St) when
    Op =:= ld64_imm; Op =:= ld_map_fd; Op =:= ld_map_value
->
    exec_loop(set_reg(advance(St), Dst, Imm band ?MASK64));
%% === Memory LDX ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, St) when
    Op =:= ldxb; Op =:= ldxh; Op =:= ldxw; Op =:= ldxdw
->
    Size = mem_size(Op),
    Addr = (get_reg(St, Src) + Off) band ?MASK64,
    case ebpf_vm_mem:read(St#vm_state.memory, Addr, Size, St#vm_state.stack) of
        {ok, Val} ->
            exec_loop(set_reg(advance(St), Dst, Val));
        {error, Reason} ->
            {error, {mem_read, Reason, Addr}}
    end;
%% === Memory STX ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, St) when
    Op =:= stxb; Op =:= stxh; Op =:= stxw; Op =:= stxdw
->
    Size = mem_size(Op),
    Addr = (get_reg(St, Dst) + Off) band ?MASK64,
    Val = get_reg(St, Src),
    case ebpf_vm_mem:write(St#vm_state.memory, Addr, Size, Val, St#vm_state.stack) of
        {ok, NewMem, NewStack} ->
            exec_loop(advance(St#vm_state{memory = NewMem, stack = NewStack}));
        {error, Reason} ->
            {error, {mem_write, Reason, Addr}}
    end;
%% === Memory ST (immediate) ===
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, St) when
    Op =:= stb; Op =:= sth; Op =:= stw; Op =:= stdw
->
    Size = mem_size(Op),
    Addr = (get_reg(St, Dst) + Off) band ?MASK64,
    case ebpf_vm_mem:write(St#vm_state.memory, Addr, Size, Imm, St#vm_state.stack) of
        {ok, NewMem, NewStack} ->
            exec_loop(advance(St#vm_state{memory = NewMem, stack = NewStack}));
        {error, Reason} ->
            {error, {mem_write, Reason, Addr}}
    end;
%% === JA (unconditional jump) ===
exec_insn(#vm_insn{op = ja, off = Off}, St) ->
    exec_loop(St#vm_state{pc = St#vm_state.pc + 1 + Off});
%% === JMP64 conditional (immediate) ===
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, St) when
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
    JmpOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, Imm band ?MASK64, 64) of
        true -> exec_loop(St#vm_state{pc = St#vm_state.pc + 1 + Off});
        false -> exec_loop(advance(St))
    end;
%% === JMP64 conditional (register) ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, St) when
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
    JmpOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, SrcVal, 64) of
        true -> exec_loop(St#vm_state{pc = St#vm_state.pc + 1 + Off});
        false -> exec_loop(advance(St))
    end;
%% === JMP32 conditional (immediate) ===
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, St) when
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
    JmpOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, Imm band ?MASK32, 32) of
        true -> exec_loop(St#vm_state{pc = St#vm_state.pc + 1 + Off});
        false -> exec_loop(advance(St))
    end;
%% === JMP32 conditional (register) ===
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, St) when
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
    JmpOp = strip_suffix(Op),
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, SrcVal, 32) of
        true -> exec_loop(St#vm_state{pc = St#vm_state.pc + 1 + Off});
        false -> exec_loop(advance(St))
    end;
%% === Endian byte-swap ===
exec_insn(#vm_insn{op = be, dst = Dst, imm = Width}, St) ->
    Val = get_reg(St, Dst),
    Result = endian_swap_be(Val, Width),
    exec_loop(set_reg(advance(St), Dst, Result));
exec_insn(#vm_insn{op = le, dst = Dst, imm = Width}, St) ->
    Val = get_reg(St, Dst),
    Result = endian_swap_le(Val, Width),
    exec_loop(set_reg(advance(St), Dst, Result));
%% === CALL ===
exec_insn(#vm_insn{op = call, imm = HelperId}, St) ->
    case ebpf_vm_helpers:call(HelperId, St, #{}) of
        {ok, RetVal, St2} ->
            exec_loop(set_reg(advance(St2), 0, RetVal band ?MASK64));
        {error, Reason} ->
            {error, {helper_error, HelperId, Reason}}
    end;
%% === Unknown ===
exec_insn(#vm_insn{op = Op}, _St) ->
    {error, {unknown_insn, Op}}.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

get_reg(#vm_state{regs = Regs}, R) ->
    maps:get(R, Regs, 0).

set_reg(#vm_state{regs = Regs} = St, R, Val) ->
    St#vm_state{regs = Regs#{R => Val band ?MASK64}}.

advance(#vm_state{pc = PC} = St) ->
    St#vm_state{pc = PC + 1}.

%% Strip _imm/_reg/_32 suffixes to get the base ALU/JMP op atom.
strip_suffix(Op) ->
    S = atom_to_list(Op),
    Base = strip_suffixes(S, [
        "64_imm",
        "64_reg",
        "32_imm",
        "32_reg",
        "_imm",
        "_reg"
    ]),
    list_to_atom(Base).

strip_suffixes(S, []) ->
    S;
strip_suffixes(S, [Suffix | Rest]) ->
    SuffLen = length(Suffix),
    case
        length(S) > SuffLen andalso
            lists:suffix(Suffix, S)
    of
        true ->
            lists:sublist(S, length(S) - SuffLen);
        false ->
            strip_suffixes(S, Rest)
    end.

%% Memory access size from opcode atom.
mem_size(Op) when Op =:= ldxb; Op =:= stxb; Op =:= stb -> 1;
mem_size(Op) when Op =:= ldxh; Op =:= stxh; Op =:= sth -> 2;
mem_size(Op) when Op =:= ldxw; Op =:= stxw; Op =:= stw -> 4;
mem_size(Op) when Op =:= ldxdw; Op =:= stxdw; Op =:= stdw -> 8.

%% Endian byte-swap helpers.
%% BPF runs on the host. On little-endian (x86):
%%   be16/be32/be64 = actual byte swap (host → big-endian)
%%   le16/le32/le64 = no-op (host → little-endian, already LE)
%% We assume little-endian host (x86/ARM LE), matching uBPF.
endian_swap_be(Val, 16) ->
    B0 = Val band 16#FF,
    B1 = (Val bsr 8) band 16#FF,
    (B0 bsl 8) bor B1;
endian_swap_be(Val, 32) ->
    B0 = Val band 16#FF,
    B1 = (Val bsr 8) band 16#FF,
    B2 = (Val bsr 16) band 16#FF,
    B3 = (Val bsr 24) band 16#FF,
    (B0 bsl 24) bor (B1 bsl 16) bor (B2 bsl 8) bor B3;
endian_swap_be(Val, 64) ->
    <<Swapped:64/big>> = <<Val:64/little>>,
    Swapped.

endian_swap_le(Val, 16) -> Val band 16#FFFF;
endian_swap_le(Val, 32) -> Val band 16#FFFFFFFF;
endian_swap_le(Val, 64) -> Val band ?MASK64.

%% Setup maps from options: [{Type, KeySize, ValSize, MaxEntries}] → ...
%% Maps get sequential FDs starting from 0 to match compiler's map IDs.
setup_maps(MapSpecs) ->
    {_, _, TabAcc, MetaAcc} = lists:foldl(
        fun({Type, KS, VS, Max}, {Idx, _FdAcc, TAcc, MAcc}) ->
            {_Fd, Tab, Meta} = ebpf_vm_maps:create(Type, KS, VS, Max),
            {Idx + 1, #{}, TAcc#{Idx => Tab}, MAcc#{Idx => Meta}}
        end,
        {0, #{}, #{}, #{}},
        MapSpecs
    ),
    {#{}, TabAcc, MetaAcc}.
