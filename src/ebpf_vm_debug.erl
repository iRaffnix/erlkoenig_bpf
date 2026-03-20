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

-module(ebpf_vm_debug).
-moduledoc """
Single-step BPF VM for the debugger.

Wraps the execution logic from ebpf_vm to allow stepping through
instructions one at a time, exposing full VM state after each step.
""".

-include("ebpf_vm.hrl").

-export([
    init/3, init/4,
    step/1,
    run_to_end/1,
    run_to_breakpoint/2,
    get_state/1,
    destroy/1
]).

-record(debug_state, {
    vm :: #vm_state{},
    status = running :: running | halted | error,
    result :: undefined | non_neg_integer() | {error, term()}
}).

-define(MASK64, 16#FFFFFFFFFFFFFFFF).
-define(MASK32, 16#FFFFFFFF).

-doc "Initialize a debug session. MapSpecs: [{Type, KeySize, ValSize, MaxEntries}]".
-spec init(binary(), map(), [{atom(), pos_integer(), pos_integer(), pos_integer()}]) ->
    {ok, #debug_state{}}.
init(ProgBin, Ctx, MapSpecs) ->
    init(ProgBin, Ctx, MapSpecs, undefined).

-doc "Initialize a debug session, transferring ETS table ownership to Owner.".
-spec init(
    binary(),
    map(),
    [{atom(), pos_integer(), pos_integer(), pos_integer()}],
    pid() | undefined
) ->
    {ok, #debug_state{}}.
init(ProgBin, Ctx, MapSpecs, Owner) ->
    {MapsTabs, MapsMeta} = ebpf_vm:create_maps(MapSpecs),
    %% Transfer ETS ownership so tables survive request handler process death
    case Owner of
        undefined ->
            ok;
        Pid when is_pid(Pid) ->
            maps:foreach(
                fun(_, Tab) ->
                    ets:give_away(Tab, Pid, debug_map)
                end,
                MapsTabs
            )
    end,
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
        insn_limit = 1000000,
        trace = false
    },
    {ok, #debug_state{vm = St}}.

-doc "Destroy a debug session, cleaning up ETS tables.".
-spec destroy(#debug_state{}) -> ok.
destroy(#debug_state{vm = VM}) ->
    ebpf_vm:destroy_maps({VM#vm_state.maps, VM#vm_state.map_meta});
destroy(_) ->
    ok.

-doc "Execute one instruction and return the updated state.".
-spec step(#debug_state{}) -> #debug_state{}.
step(#debug_state{status = halted} = DS) ->
    DS;
step(#debug_state{status = error} = DS) ->
    DS;
step(#debug_state{vm = #vm_state{pc = PC, insn_count = Count}} = DS) when PC >= Count ->
    DS#debug_state{status = error, result = {error, {pc_oob, PC}}};
step(#debug_state{vm = #vm_state{insn_executed = N, insn_limit = Limit}} = DS) when
    N >= Limit
->
    DS#debug_state{status = error, result = {error, insn_limit_exceeded}};
step(#debug_state{vm = #vm_state{pc = PC, insns = Insns} = St} = DS) ->
    Insn = array:get(PC, Insns),
    St2 = St#vm_state{insn_executed = St#vm_state.insn_executed + 1},
    exec_insn(Insn, DS#debug_state{vm = St2}).

-doc "Run until halt or error (max insn_limit steps).".
-spec run_to_end(#debug_state{}) -> #debug_state{}.
run_to_end(#debug_state{status = running} = DS) ->
    run_to_end(step(DS));
run_to_end(DS) ->
    DS.

-doc "Run until a breakpoint PC is hit, or halt/error.".
-spec run_to_breakpoint(#debug_state{}, sets:set(non_neg_integer())) -> #debug_state{}.
run_to_breakpoint(#debug_state{status = running} = DS, BPs) ->
    DS2 = step(DS),
    case DS2#debug_state.status of
        running ->
            NewPC = (DS2#debug_state.vm)#vm_state.pc,
            case sets:is_element(NewPC, BPs) of
                true -> DS2;
                false -> run_to_breakpoint(DS2, BPs)
            end;
        _ ->
            DS2
    end;
run_to_breakpoint(DS, _BPs) ->
    DS.

-doc "Export VM state as a JSON-friendly map.".
-spec get_state(#debug_state{}) -> map().
get_state(#debug_state{vm = VM, status = Status, result = Result}) ->
    Regs = VM#vm_state.regs,
    RegList = [#{index => I, value => fmt_hex64(maps:get(I, Regs, 0))} || I <- lists:seq(0, 10)],
    Stack = VM#vm_state.stack,
    %% Find active stack region (from FP downward)
    StackSlots = extract_stack_slots(Stack, maps:get(10, Regs, 0)),
    %% Map entries
    MapEntries = extract_maps(VM#vm_state.maps, VM#vm_state.map_meta),
    #{
        pc => VM#vm_state.pc,
        insn_executed => VM#vm_state.insn_executed,
        insn_count => VM#vm_state.insn_count,
        status => Status,
        result =>
            case Result of
                undefined -> null;
                {error, Err} -> iolist_to_binary(io_lib:format("~p", [Err]));
                N when is_integer(N) -> N
            end,
        registers => RegList,
        stack => StackSlots,
        maps => MapEntries
    }.

%%% ===================================================================
%%% Instruction execution (mirrors ebpf_vm but returns state instead
%%% of tail-calling exec_loop)
%%% ===================================================================

exec_insn(#vm_insn{op = exit_insn}, #debug_state{vm = #vm_state{regs = Regs}} = DS) ->
    R0 = maps:get(0, Regs, 0),
    DS#debug_state{status = halted, result = R0};
exec_insn(#vm_insn{op = nop}, #debug_state{vm = St} = DS) ->
    DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1}};
%% ALU64 immediate
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, Imm band ?MASK64, 64),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
exec_insn(#vm_insn{op = neg64, dst = Dst}, DS) ->
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(neg, DstVal, 0, 64),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
%% ALU64 register
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, SrcVal, 64),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
%% ALU32 immediate
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, Imm band ?MASK32, 32),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
exec_insn(#vm_insn{op = neg32, dst = Dst}, DS) ->
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    Result = ebpf_vm_alu:exec(neg, DstVal, 0, 32),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
%% ALU32 register
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    Result = ebpf_vm_alu:exec(AluOp, DstVal, SrcVal, 32),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
%% LD64_IMM / LD_MAP_FD
exec_insn(#vm_insn{op = Op, dst = Dst, imm = Imm}, DS) when
    Op =:= ld64_imm; Op =:= ld_map_fd; Op =:= ld_map_value
->
    St = DS#debug_state.vm,
    DS#debug_state{vm = set_reg(advance(St), Dst, Imm band ?MASK64)};
%% Memory LDX
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, DS) when
    Op =:= ldxb; Op =:= ldxh; Op =:= ldxw; Op =:= ldxdw
->
    St = DS#debug_state.vm,
    Size = mem_size(Op),
    Addr = (get_reg(St, Src) + Off) band ?MASK64,
    case ebpf_vm_mem:read(St#vm_state.memory, Addr, Size, St#vm_state.stack) of
        {ok, Val} ->
            DS#debug_state{vm = set_reg(advance(St), Dst, Val)};
        {error, Reason} ->
            DS#debug_state{status = error, result = {error, {mem_read, Reason, Addr}}}
    end;
%% Memory STX
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, DS) when
    Op =:= stxb; Op =:= stxh; Op =:= stxw; Op =:= stxdw
->
    St = DS#debug_state.vm,
    Size = mem_size(Op),
    Addr = (get_reg(St, Dst) + Off) band ?MASK64,
    Val = get_reg(St, Src),
    case ebpf_vm_mem:write(St#vm_state.memory, Addr, Size, Val, St#vm_state.stack) of
        {ok, NewMem, NewStack} ->
            DS#debug_state{vm = advance(St#vm_state{memory = NewMem, stack = NewStack})};
        {error, Reason} ->
            DS#debug_state{status = error, result = {error, {mem_write, Reason, Addr}}}
    end;
%% Memory ST (immediate)
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, DS) when
    Op =:= stb; Op =:= sth; Op =:= stw; Op =:= stdw
->
    St = DS#debug_state.vm,
    Size = mem_size(Op),
    Addr = (get_reg(St, Dst) + Off) band ?MASK64,
    case ebpf_vm_mem:write(St#vm_state.memory, Addr, Size, Imm, St#vm_state.stack) of
        {ok, NewMem, NewStack} ->
            DS#debug_state{vm = advance(St#vm_state{memory = NewMem, stack = NewStack})};
        {error, Reason} ->
            DS#debug_state{status = error, result = {error, {mem_write, Reason, Addr}}}
    end;
%% JA
exec_insn(#vm_insn{op = ja, off = Off}, DS) ->
    St = DS#debug_state.vm,
    DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1 + Off}};
%% JMP64 conditional (immediate)
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, Imm band ?MASK64, 64) of
        true -> DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1 + Off}};
        false -> DS#debug_state{vm = advance(St)}
    end;
%% JMP64 conditional (register)
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, SrcVal, 64) of
        true -> DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1 + Off}};
        false -> DS#debug_state{vm = advance(St)}
    end;
%% JMP32 conditional (immediate)
exec_insn(#vm_insn{op = Op, dst = Dst, off = Off, imm = Imm}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, Imm band ?MASK32, 32) of
        true -> DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1 + Off}};
        false -> DS#debug_state{vm = advance(St)}
    end;
%% JMP32 conditional (register)
exec_insn(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}, DS) when
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
    St = DS#debug_state.vm,
    DstVal = get_reg(St, Dst),
    SrcVal = get_reg(St, Src),
    case ebpf_vm_jmp:eval(JmpOp, DstVal, SrcVal, 32) of
        true -> DS#debug_state{vm = St#vm_state{pc = St#vm_state.pc + 1 + Off}};
        false -> DS#debug_state{vm = advance(St)}
    end;
%% Endian
exec_insn(#vm_insn{op = be, dst = Dst, imm = Width}, DS) ->
    St = DS#debug_state.vm,
    Val = get_reg(St, Dst),
    Result = endian_swap_be(Val, Width),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
exec_insn(#vm_insn{op = le, dst = Dst, imm = Width}, DS) ->
    St = DS#debug_state.vm,
    Val = get_reg(St, Dst),
    Result = endian_swap_le(Val, Width),
    DS#debug_state{vm = set_reg(advance(St), Dst, Result)};
%% CALL
exec_insn(#vm_insn{op = call, imm = HelperId}, DS) ->
    St = DS#debug_state.vm,
    case ebpf_vm_helpers:call(HelperId, St, #{}) of
        {ok, RetVal, St2} ->
            DS#debug_state{vm = set_reg(advance(St2), 0, RetVal band ?MASK64)};
        {error, Reason} ->
            DS#debug_state{status = error, result = {error, {helper_error, HelperId, Reason}}}
    end;
%% Unknown
exec_insn(#vm_insn{op = Op}, DS) ->
    DS#debug_state{status = error, result = {error, {unknown_insn, Op}}}.

%%% ===================================================================
%%% Helpers (mirrored from ebpf_vm)
%%% ===================================================================

get_reg(#vm_state{regs = Regs}, R) -> maps:get(R, Regs, 0).

set_reg(#vm_state{regs = Regs} = St, R, Val) ->
    St#vm_state{regs = Regs#{R => Val band ?MASK64}}.

advance(#vm_state{pc = PC} = St) -> St#vm_state{pc = PC + 1}.

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
    case length(S) > SuffLen andalso lists:suffix(Suffix, S) of
        true -> lists:sublist(S, length(S) - SuffLen);
        false -> strip_suffixes(S, Rest)
    end.

mem_size(Op) when Op =:= ldxb; Op =:= stxb; Op =:= stb -> 1;
mem_size(Op) when Op =:= ldxh; Op =:= stxh; Op =:= sth -> 2;
mem_size(Op) when Op =:= ldxw; Op =:= stxw; Op =:= stw -> 4;
mem_size(Op) when Op =:= ldxdw; Op =:= stxdw; Op =:= stdw -> 8.

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

%% Format 64-bit value as hex string (safe for JS)
fmt_hex64(Val) ->
    iolist_to_binary(io_lib:format("0x~16.16.0B", [Val band 16#FFFFFFFFFFFFFFFF])).

%% Extract non-zero stack slots as [{Offset, HexValue}]
extract_stack_slots(Stack, _FP) ->
    extract_stack_slots_loop(Stack, 0, []).

extract_stack_slots_loop(<<>>, _Off, Acc) ->
    lists:reverse(Acc);
extract_stack_slots_loop(<<Val:64/little-unsigned, Rest/binary>>, Off, Acc) ->
    case Val of
        0 ->
            extract_stack_slots_loop(Rest, Off + 8, Acc);
        _ ->
            extract_stack_slots_loop(
                Rest,
                Off + 8,
                [#{offset => -(512 - Off), value => fmt_hex64(Val)} | Acc]
            )
    end;
extract_stack_slots_loop(_, _Off, Acc) ->
    lists:reverse(Acc).

%% Extract all map entries
extract_maps(MapsTabs, MapsMeta) ->
    maps:fold(
        fun(Fd, Tab, Acc) ->
            Meta = maps:get(Fd, MapsMeta),
            Entries =
                try
                    ets:tab2list(Tab)
                catch
                    _:_ -> []
                end,
            FormattedEntries = lists:map(
                fun(Entry) ->
                    Key = element(1, Entry),
                    Val = element(2, Entry),
                    #{
                        key => format_map_bytes(Key),
                        value => format_map_bytes(Val)
                    }
                end,
                Entries
            ),
            [
                #{
                    fd => Fd,
                    type => Meta#map_meta.type,
                    key_size => Meta#map_meta.key_size,
                    val_size => Meta#map_meta.val_size,
                    entries => FormattedEntries
                }
                | Acc
            ]
        end,
        [],
        MapsTabs
    ).

format_map_bytes(Bin) when is_binary(Bin) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]).
