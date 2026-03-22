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

-module(ebl_pre_verify).
-moduledoc """
Static BPF bytecode pre-verifier.

Performs checks similar to the Linux kernel verifier but without
requiring root or kernel access.  Catches common errors early:
instruction limits, missing exit, invalid jumps, stack overflows,
division by zero, uninitialized registers, null pointer derefs,
R10 write protection, stack alignment, unreachable code, and
helper argument type checking.
""".

-include("ebpf_vm.hrl").

-export([check/1, check/2]).

-type reg_val() ::
    not_init
    | {scalar, {integer(), integer()}}
    | {ptr_to_ctx}
    | {ptr_to_stack, integer()}
    | {ptr_to_packet, integer()}
    | {ptr_to_map_value_or_null}
    | {ptr_to_map_value}
    | {ptr_to_map}
    | init.

-type error() ::
    {
        instruction_limit_exceeded
        | invalid_jump_target
        | invalid_opcode
        | invalid_stack_access
        | possible_null_deref
        | stack_overflow
        | uninitialized_register,
        integer(),
        non_neg_integer()
    }
    | {no_exit_instruction}
    | {division_by_zero_imm, non_neg_integer()}
    | {r10_write, non_neg_integer()}
    | {stack_misalign, integer(), 2 | 4 | 8, non_neg_integer()}
    | {unreachable_code, non_neg_integer()}
    | {invalid_helper_arg, non_neg_integer(), pos_integer(), atom(), reg_val(), non_neg_integer()}.

-export_type([error/0]).

-spec check(binary()) -> ok | {error, [error(), ...]}.
check(Bytecode) ->
    check(Bytecode, #{}).

-spec check(binary(), map()) -> ok | {error, [error(), ...]}.
check(Bytecode, Opts) ->
    InsnLimit = maps:get(insn_limit, Opts, 1000000),
    StackLimit = maps:get(stack_limit, Opts, 512),
    try ebpf_vm_decode:decode_program(Bytecode) of
        InsnArray ->
            NumInsns = array:size(InsnArray),
            Insns = array:to_list(InsnArray),
            %% Build set of second-half-of-ld64 PCs
            Ld64Seconds = ld64_second_slots(Insns, 0, #{}),
            Errors =
                check_insn_limit(NumInsns, InsnLimit) ++
                    check_exit_exists(Insns) ++
                    check_invalid_opcodes(Insns) ++
                    check_jump_targets(Insns, NumInsns, Ld64Seconds) ++
                    check_stack_bounds(Insns, StackLimit) ++
                    check_div_by_zero(Insns) ++
                    check_abstract(InsnArray, NumInsns, StackLimit, Ld64Seconds),
            case Errors of
                [] -> ok;
                _ -> {error, Errors}
            end
    catch
        _:_ ->
            {error, [{invalid_opcode, 0, 0}]}
    end.

%%% ===================================================================
%%% P1: Instruction limit
%%% ===================================================================

check_insn_limit(NumInsns, Limit) when NumInsns > Limit ->
    [{instruction_limit_exceeded, NumInsns, Limit}];
check_insn_limit(_, _) ->
    [].

%%% ===================================================================
%%% P2: Exit instruction exists
%%% ===================================================================

check_exit_exists([]) ->
    [{no_exit_instruction}];
check_exit_exists(Insns) ->
    HasExit = lists:any(
        fun
            (#vm_insn{op = exit_insn}) -> true;
            (_) -> false
        end,
        Insns
    ),
    case HasExit of
        true -> [];
        false -> [{no_exit_instruction}]
    end.

%%% ===================================================================
%%% P3: Valid opcodes
%%% ===================================================================

check_invalid_opcodes(Insns) ->
    check_invalid_opcodes(Insns, 0).

check_invalid_opcodes([], _PC) ->
    [];
check_invalid_opcodes([#vm_insn{op = {unknown, Code}} | Rest], PC) ->
    [{invalid_opcode, Code, PC} | check_invalid_opcodes(Rest, PC + 1)];
check_invalid_opcodes([_ | Rest], PC) ->
    check_invalid_opcodes(Rest, PC + 1).

%%% ===================================================================
%%% P4: Jump target validity
%%% ===================================================================

check_jump_targets(Insns, NumInsns, Ld64Seconds) ->
    check_jump_targets(Insns, 0, NumInsns, Ld64Seconds).

check_jump_targets([], _PC, _NumInsns, _Ld64Seconds) ->
    [];
check_jump_targets([Insn | Rest], PC, NumInsns, Ld64Seconds) ->
    Errors =
        case is_jump(Insn#vm_insn.op) of
            {true, unconditional} ->
                Target = PC + 1 + Insn#vm_insn.off,
                validate_target(Target, PC, NumInsns, Ld64Seconds);
            {true, conditional} ->
                Target = PC + 1 + Insn#vm_insn.off,
                validate_target(Target, PC, NumInsns, Ld64Seconds);
            false ->
                []
        end,
    Errors ++ check_jump_targets(Rest, PC + 1, NumInsns, Ld64Seconds).

validate_target(Target, PC, NumInsns, Ld64Seconds) ->
    if
        Target < 0 ->
            [{invalid_jump_target, Target, PC}];
        Target >= NumInsns ->
            [{invalid_jump_target, Target, PC}];
        true ->
            case maps:is_key(Target, Ld64Seconds) of
                true -> [{invalid_jump_target, Target, PC}];
                false -> []
            end
    end.

is_jump(ja) ->
    {true, unconditional};
is_jump(Op) ->
    case atom_to_list(Op) of
        "j" ++ _ -> {true, conditional};
        _ -> false
    end.

%%% ===================================================================
%%% P5: Stack bounds + P10: Stack alignment
%%% ===================================================================

check_stack_bounds(Insns, StackLimit) ->
    check_stack_bounds(Insns, 0, StackLimit).

check_stack_bounds([], _PC, _StackLimit) ->
    [];
check_stack_bounds([Insn | Rest], PC, StackLimit) ->
    Errors =
        case is_stack_access(Insn) of
            {true, Offset} ->
                BoundsErrors =
                    if
                        Offset < -StackLimit ->
                            [{stack_overflow, Offset, StackLimit}];
                        Offset >= 0 ->
                            [{invalid_stack_access, Offset, PC}];
                        true ->
                            []
                    end,
                AlignErrors = check_stack_alignment(Insn#vm_insn.op, Offset, PC),
                BoundsErrors ++ AlignErrors;
            false ->
                []
        end,
    Errors ++ check_stack_bounds(Rest, PC + 1, StackLimit).

%% P10: Stack alignment check
check_stack_alignment(Op, Offset, PC) ->
    AbsOff = abs(Offset),
    case Op of
        ldxdw -> check_align(AbsOff, 8, Offset, PC);
        stxdw -> check_align(AbsOff, 8, Offset, PC);
        stdw -> check_align(AbsOff, 8, Offset, PC);
        ldxw -> check_align(AbsOff, 4, Offset, PC);
        stxw -> check_align(AbsOff, 4, Offset, PC);
        stw -> check_align(AbsOff, 4, Offset, PC);
        ldxh -> check_align(AbsOff, 2, Offset, PC);
        stxh -> check_align(AbsOff, 2, Offset, PC);
        sth -> check_align(AbsOff, 2, Offset, PC);
        %% byte ops and others: no alignment requirement
        _ -> []
    end.

check_align(AbsOff, Size, Offset, PC) ->
    case AbsOff rem Size of
        0 -> [];
        _ -> [{stack_misalign, Offset, Size, PC}]
    end.

%% Check if instruction accesses stack (base register = R10)
is_stack_access(#vm_insn{op = Op, dst = Dst, src = Src, off = Off}) ->
    case Op of
        ldxw -> is_stack_reg(Src, Off);
        ldxh -> is_stack_reg(Src, Off);
        ldxb -> is_stack_reg(Src, Off);
        ldxdw -> is_stack_reg(Src, Off);
        stxw -> is_stack_reg(Dst, Off);
        stxh -> is_stack_reg(Dst, Off);
        stxb -> is_stack_reg(Dst, Off);
        stxdw -> is_stack_reg(Dst, Off);
        stw -> is_stack_reg(Dst, Off);
        sth -> is_stack_reg(Dst, Off);
        stb -> is_stack_reg(Dst, Off);
        stdw -> is_stack_reg(Dst, Off);
        _ -> false
    end.

is_stack_reg(10, Off) -> {true, Off};
is_stack_reg(_, _Off) -> false.

%%% ===================================================================
%%% P6: Division by zero (immediate)
%%% ===================================================================

check_div_by_zero(Insns) ->
    check_div_by_zero(Insns, 0).

check_div_by_zero([], _PC) ->
    [];
check_div_by_zero([#vm_insn{op = Op, imm = 0} | Rest], PC) when
    Op =:= div64_imm;
    Op =:= mod64_imm;
    Op =:= div32_imm;
    Op =:= mod32_imm
->
    [{division_by_zero_imm, PC} | check_div_by_zero(Rest, PC + 1)];
check_div_by_zero([_ | Rest], PC) ->
    check_div_by_zero(Rest, PC + 1).

%%% ===================================================================
%%% P7-P12: Abstract interpretation
%%% ===================================================================

check_abstract(InsnArray, NumInsns, _StackLimit, Ld64Seconds) ->
    %% Initial register state: R1 = ctx, R10 = frame pointer, rest not_init
    InitRegs = maps:from_list([{R, not_init} || R <- lists:seq(0, 10)]),
    InitRegs1 = InitRegs#{1 => {ptr_to_ctx}, 10 => {ptr_to_stack, 0}},
    Worklist = [{0, InitRegs1}],
    Visited = #{},
    HasJumps = program_has_jumps(InsnArray, NumInsns),
    {Errors, FinalVisited} =
        interpret_loop(InsnArray, NumInsns, Worklist, Visited, [], Ld64Seconds),
    UnreachableErrors =
        case HasJumps of
            true -> check_unreachable(FinalVisited, NumInsns, Ld64Seconds);
            false -> []
        end,
    Errors ++ UnreachableErrors.

program_has_jumps(InsnArray, NumInsns) ->
    program_has_jumps(InsnArray, 0, NumInsns).

program_has_jumps(_InsnArray, PC, NumInsns) when PC >= NumInsns ->
    false;
program_has_jumps(InsnArray, PC, NumInsns) ->
    Insn = array:get(PC, InsnArray),
    case is_jump(Insn#vm_insn.op) of
        {true, _} -> true;
        false -> program_has_jumps(InsnArray, PC + 1, NumInsns)
    end.

interpret_loop(_InsnArray, _NumInsns, [], Visited, Errors, _Ld64Seconds) ->
    {lists:usort(Errors), Visited};
interpret_loop(InsnArray, NumInsns, [{PC, Regs} | Rest], Visited, Errors, Ld64Seconds) ->
    if
        PC < 0; PC >= NumInsns ->
            interpret_loop(InsnArray, NumInsns, Rest, Visited, Errors, Ld64Seconds);
        true ->
            case maps:find(PC, Visited) of
                {ok, OldRegs} ->
                    Merged = merge_regs(OldRegs, Regs),
                    case Merged =:= OldRegs of
                        true ->
                            %% No change, skip
                            interpret_loop(InsnArray, NumInsns, Rest, Visited, Errors, Ld64Seconds);
                        false ->
                            Visited1 = Visited#{PC => Merged},
                            {NewErrors, Successors} = analyze_insn(
                                InsnArray, PC, Merged, NumInsns, Ld64Seconds
                            ),
                            interpret_loop(
                                InsnArray,
                                NumInsns,
                                Successors ++ Rest,
                                Visited1,
                                NewErrors ++ Errors,
                                Ld64Seconds
                            )
                    end;
                error ->
                    Visited1 = Visited#{PC => Regs},
                    {NewErrors, Successors} = analyze_insn(
                        InsnArray, PC, Regs, NumInsns, Ld64Seconds
                    ),
                    interpret_loop(
                        InsnArray,
                        NumInsns,
                        Successors ++ Rest,
                        Visited1,
                        NewErrors ++ Errors,
                        Ld64Seconds
                    )
            end
    end.

%%% ===================================================================
%%% Register merge (abstract join)
%%% ===================================================================

merge_regs(Regs1, Regs2) ->
    maps:map(
        fun(K, V1) ->
            V2 = maps:get(K, Regs2, not_init),
            merge_val(V1, V2)
        end,
        Regs1
    ).

merge_val(Same, Same) ->
    Same;
merge_val(not_init, _) ->
    not_init;
merge_val(_, not_init) ->
    not_init;
merge_val({scalar, {A, B}}, {scalar, {C, D}}) ->
    %% Widen: merge the ranges, but collapse to init if the resulting range
    %% is wider than either input.  This guarantees convergence in loops —
    %% after one widening iteration, the value becomes init and stays init.
    NewMin = min(A, C),
    NewMax = max(B, D),
    SpanOld1 = B - A,
    SpanOld2 = D - C,
    SpanNew = NewMax - NewMin,
    case SpanNew > max(SpanOld1, SpanOld2) of
        true -> init;
        false -> {scalar, {NewMin, NewMax}}
    end;
merge_val({ptr_to_map_value_or_null}, {ptr_to_map_value}) ->
    {ptr_to_map_value_or_null};
merge_val({ptr_to_map_value}, {ptr_to_map_value_or_null}) ->
    {ptr_to_map_value_or_null};
merge_val(_, _) ->
    %% Different pointer types, ptr+scalar, or unknown combinations → init (safe fallback)
    init.

%%% ===================================================================
%%% Instruction analysis with type propagation
%%% ===================================================================

analyze_insn(InsnArray, PC, Regs, _NumInsns, _Ld64Seconds) ->
    Insn = array:get(PC, InsnArray),
    Op = Insn#vm_insn.op,
    Dst = Insn#vm_insn.dst,
    Src = Insn#vm_insn.src,
    Off = Insn#vm_insn.off,
    Imm = Insn#vm_insn.imm,
    case Op of
        exit_insn ->
            %% Check R0 is readable
            E = check_read(0, Regs, PC),
            {E, []};
        call ->
            %% P12: Helper argument type checking
            HelperErrors = check_helper_args(Imm, Regs, PC),
            %% After call: R0 = result, R1-R5 clobbered
            Regs1 = Regs#{
                0 => init,
                1 => not_init,
                2 => not_init,
                3 => not_init,
                4 => not_init,
                5 => not_init
            },
            %% Special case: call 1 = map_lookup_elem -> R0 = maybe null
            Regs2 =
                case Imm of
                    1 -> Regs1#{0 => {ptr_to_map_value_or_null}};
                    _ -> Regs1
                end,
            {HelperErrors, [{PC + 1, Regs2}]};
        ja ->
            Target = PC + 1 + Off,
            {[], [{Target, Regs}]};
        nop ->
            %% Second slot of LD_IMM64 — just fall through
            {[], [{PC + 1, Regs}]};
        _ ->
            case classify_op(Op) of
                {alu_imm, AluOp} ->
                    %% P9: R10 write protection
                    R10Err = check_r10_write(Dst, PC),
                    %% dst = dst OP imm; read dst, write dst
                    E = check_read(Dst, Regs, PC),
                    DstVal = maps:get(Dst, Regs, not_init),
                    NewDst = compute_alu_imm(AluOp, DstVal, Imm),
                    Regs1 = Regs#{Dst => NewDst},
                    {R10Err ++ E, [{PC + 1, Regs1}]};
                {alu_reg, AluOp} ->
                    %% P9: R10 write protection
                    R10Err = check_r10_write(Dst, PC),
                    %% dst = dst OP src; read dst+src, write dst
                    E = check_read(Dst, Regs, PC) ++ check_read(Src, Regs, PC),
                    DstVal = maps:get(Dst, Regs, not_init),
                    SrcVal = maps:get(Src, Regs, not_init),
                    NewDst = compute_alu_reg(AluOp, DstVal, SrcVal),
                    Regs1 = Regs#{Dst => NewDst},
                    {R10Err ++ E, [{PC + 1, Regs1}]};
                {mov_imm} ->
                    %% P9: R10 write protection
                    R10Err = check_r10_write(Dst, PC),
                    %% dst = imm; write dst (no read)
                    Regs1 = Regs#{Dst => {scalar, {Imm, Imm}}},
                    {R10Err, [{PC + 1, Regs1}]};
                {mov_reg} ->
                    %% P9: R10 write protection
                    R10Err = check_r10_write(Dst, PC),
                    %% dst = src; read src, write dst
                    E = check_read(Src, Regs, PC),
                    %% Propagate type from src
                    SrcVal = maps:get(Src, Regs, not_init),
                    Regs1 = Regs#{Dst => SrcVal},
                    {R10Err ++ E, [{PC + 1, Regs1}]};
                {neg} ->
                    %% P9: R10 write protection
                    R10Err = check_r10_write(Dst, PC),
                    %% dst = -dst; read+write dst
                    E = check_read(Dst, Regs, PC),
                    DstVal = maps:get(Dst, Regs, not_init),
                    NewDst =
                        case DstVal of
                            {scalar, {A, B}} -> {scalar, {-B, -A}};
                            _ -> init
                        end,
                    Regs1 = Regs#{Dst => NewDst},
                    {R10Err ++ E, [{PC + 1, Regs1}]};
                {ld64} ->
                    %% dst = imm64; write dst, skip next slot (nop)
                    %% Distinguish ld_map_fd from plain ld64_imm
                    NewDst =
                        case Op of
                            ld_map_fd -> {ptr_to_map};
                            _ -> init
                        end,
                    Regs1 = Regs#{Dst => NewDst},
                    {[], [{PC + 2, Regs1}]};
                {ldx} ->
                    %% dst = [src + off]; read src, write dst
                    E =
                        check_read(Src, Regs, PC) ++
                            check_deref(Src, Regs, PC),
                    %% Result depends on base register type, but always init
                    Regs1 = Regs#{Dst => init},
                    {E, [{PC + 1, Regs1}]};
                {stx} ->
                    %% [dst + off] = src; read src+dst — does NOT write to register Dst
                    E = check_read(Src, Regs, PC) ++ check_read(Dst, Regs, PC),
                    {E, [{PC + 1, Regs}]};
                {st_imm} ->
                    %% [dst + off] = imm; read dst — does NOT write to register Dst
                    E = check_read(Dst, Regs, PC),
                    {E, [{PC + 1, Regs}]};
                {cond_jmp_imm} ->
                    %% Conditional: read dst, branch to PC+1 and PC+1+off
                    E = check_read(Dst, Regs, PC),
                    Target = PC + 1 + Off,
                    %% NULL check analysis for P8
                    {RegsFall, RegsBranch} = null_check_split(Op, Dst, Imm, Regs),
                    {E, [{PC + 1, RegsFall}, {Target, RegsBranch}]};
                {cond_jmp_reg} ->
                    %% Conditional: read dst+src, branch
                    E = check_read(Dst, Regs, PC) ++ check_read(Src, Regs, PC),
                    Target = PC + 1 + Off,
                    {RegsFall, RegsBranch} = null_check_split_reg(Op, Dst, Src, Regs),
                    {E, [{PC + 1, RegsFall}, {Target, RegsBranch}]};
                unknown ->
                    {[], [{PC + 1, Regs}]}
            end
    end.

%%% ===================================================================
%%% P9: R10 write protection
%%% ===================================================================

check_r10_write(10, PC) -> [{r10_write, PC}];
check_r10_write(_, _PC) -> [].

%%% ===================================================================
%%% ALU type computation
%%% ===================================================================

compute_alu_imm(add, {scalar, {A, B}}, Imm) ->
    {scalar, {A + Imm, B + Imm}};
compute_alu_imm(add, {ptr_to_stack, Off}, Imm) ->
    {ptr_to_stack, Off + Imm};
compute_alu_imm(sub, {scalar, {A, B}}, Imm) ->
    {scalar, {A - Imm, B - Imm}};
compute_alu_imm(add, {ptr_to_ctx}, _Imm) ->
    init;
compute_alu_imm(add, {ptr_to_packet, _}, _Imm) ->
    init;
compute_alu_imm(add, {ptr_to_map_value}, _Imm) ->
    init;
compute_alu_imm(add, {ptr_to_map_value_or_null}, _Imm) ->
    init;
compute_alu_imm(add, {ptr_to_map}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_ctx}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_packet, _}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_map_value}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_map_value_or_null}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_map}, _Imm) ->
    init;
compute_alu_imm(sub, {ptr_to_stack, _}, _Imm) ->
    init;
compute_alu_imm(_Op, {scalar, _}, _Imm) ->
    {scalar, {0, 16#ffffffffffffffff}};
compute_alu_imm(_Op, init, _Imm) ->
    init;
compute_alu_imm(_Op, not_init, _Imm) ->
    not_init;
compute_alu_imm(_Op, _, _Imm) ->
    init.

compute_alu_reg(add, {scalar, {A, B}}, {scalar, {C, D}}) ->
    {scalar, {A + C, B + D}};
compute_alu_reg(_Op, {scalar, _}, {scalar, _}) ->
    {scalar, {0, 16#ffffffffffffffff}};
compute_alu_reg(_Op, {scalar, _}, _) ->
    init;
compute_alu_reg(_Op, _, {scalar, _}) ->
    init;
compute_alu_reg(_Op, init, _) ->
    init;
compute_alu_reg(_Op, _, init) ->
    init;
compute_alu_reg(_Op, not_init, _) ->
    not_init;
compute_alu_reg(_Op, _, not_init) ->
    not_init;
compute_alu_reg(_Op, _, _) ->
    init.

%%% ===================================================================
%%% P12: Helper argument type checking
%%% ===================================================================

check_helper_args(1, Regs, PC) ->
    %% map_lookup_elem: R1 = map, R2 = key (stack ptr)
    check_helper_arg(1, 1, ptr_to_map, Regs, PC) ++
        check_helper_arg(1, 2, ptr_to_stack, Regs, PC);
check_helper_args(2, Regs, PC) ->
    %% map_update_elem: R1 = map, R2 = key, R3 = value
    check_helper_arg(2, 1, ptr_to_map, Regs, PC) ++
        check_helper_arg(2, 2, ptr_to_stack, Regs, PC) ++
        check_helper_arg(2, 3, ptr_to_stack, Regs, PC);
check_helper_args(3, Regs, PC) ->
    %% map_delete_elem: R1 = map, R2 = key
    check_helper_arg(3, 1, ptr_to_map, Regs, PC) ++
        check_helper_arg(3, 2, ptr_to_stack, Regs, PC);
check_helper_args(_HelperID, _Regs, _PC) ->
    [].

check_helper_arg(HelperID, ArgN, Expected, Regs, PC) ->
    Val = maps:get(ArgN, Regs, not_init),
    case is_acceptable_helper_arg(Expected, Val) of
        true -> [];
        false -> [{invalid_helper_arg, HelperID, ArgN, Expected, Val, PC}]
    end.

%% `init` (generic initialized) is always acceptable — be lenient
is_acceptable_helper_arg(_Expected, init) -> true;
%% not_init is never acceptable
is_acceptable_helper_arg(_Expected, not_init) -> false;
%% Exact type match
is_acceptable_helper_arg(ptr_to_map, {ptr_to_map}) -> true;
is_acceptable_helper_arg(ptr_to_stack, {ptr_to_stack, _}) -> true;
%% Definite nonzero scalar where a pointer is needed: reject.
%% A scalar {0,0} might be a placeholder/null and is accepted leniently.
is_acceptable_helper_arg(ptr_to_map, {scalar, {Min, _}}) when Min > 0 -> false;
is_acceptable_helper_arg(ptr_to_stack, {scalar, {Min, _}}) when Min > 0 -> false;
%% Zero-valued scalars and other initialized values — accept leniently
is_acceptable_helper_arg(_Expected, _Val) -> true.

%%% ===================================================================
%%% Register checks
%%% ===================================================================

%% Check that a register is initialized before reading
check_read(Reg, Regs, PC) ->
    case maps:get(Reg, Regs, not_init) of
        not_init -> [{uninitialized_register, Reg, PC}];
        _ -> []
    end.

%% Check for possible null dereference
check_deref(Reg, Regs, PC) ->
    case maps:get(Reg, Regs, not_init) of
        {ptr_to_map_value_or_null} -> [{possible_null_deref, Reg, PC}];
        _ -> []
    end.

%%% ===================================================================
%%% Null-check splits
%%% ===================================================================

%% Handle null-check splits for jeq/jne with immediate 0
%% jeq Dst, 0, +off  →  fall-through: Dst != 0 (not null), branch: Dst == 0
%% jne Dst, 0, +off  →  fall-through: Dst == 0, branch: Dst != 0 (not null)
null_check_split(Op, Dst, 0, Regs) when Op =:= jeq_imm; Op =:= jeq32_imm ->
    DstVal = maps:get(Dst, Regs, not_init),
    case DstVal of
        {ptr_to_map_value_or_null} ->
            %% fall-through = not-equal (not null), branch = equal (null)
            {Regs#{Dst => {ptr_to_map_value}}, Regs};
        _ ->
            {Regs, Regs}
    end;
null_check_split(Op, Dst, 0, Regs) when Op =:= jne_imm; Op =:= jne32_imm ->
    DstVal = maps:get(Dst, Regs, not_init),
    case DstVal of
        {ptr_to_map_value_or_null} ->
            %% fall-through = equal (null), branch = not-equal (not null)
            {Regs, Regs#{Dst => {ptr_to_map_value}}};
        _ ->
            {Regs, Regs}
    end;
null_check_split(_Op, _Dst, _Imm, Regs) ->
    {Regs, Regs}.

null_check_split_reg(Op, Dst, _Src, Regs) when Op =:= jeq_reg; Op =:= jeq32_reg ->
    %% We cannot statically know if Src == 0, so be conservative: no refinement
    DstVal = maps:get(Dst, Regs, not_init),
    case DstVal of
        {ptr_to_map_value_or_null} ->
            %% Conservative: treat both paths as still maybe_null
            {Regs, Regs};
        _ ->
            {Regs, Regs}
    end;
null_check_split_reg(_Op, _Dst, _Src, Regs) ->
    {Regs, Regs}.

%%% ===================================================================
%%% P11: Unreachable code detection
%%% ===================================================================

check_unreachable(Visited, NumInsns, Ld64Seconds) ->
    check_unreachable(Visited, 0, NumInsns, Ld64Seconds).

check_unreachable(_Visited, PC, NumInsns, _Ld64Seconds) when PC >= NumInsns ->
    [];
check_unreachable(Visited, PC, NumInsns, Ld64Seconds) ->
    Rest = check_unreachable(Visited, PC + 1, NumInsns, Ld64Seconds),
    case maps:is_key(PC, Ld64Seconds) of
        true ->
            %% LD64 second slot — skip
            Rest;
        false ->
            case maps:is_key(PC, Visited) of
                true -> Rest;
                false -> [{unreachable_code, PC} | Rest]
            end
    end.

%%% ===================================================================
%%% Instruction classification
%%% ===================================================================

classify_op(mov64_imm) ->
    {mov_imm};
classify_op(mov32_imm) ->
    {mov_imm};
classify_op(mov64_reg) ->
    {mov_reg};
classify_op(mov32_reg) ->
    {mov_reg};
classify_op(neg64) ->
    {neg};
classify_op(neg32) ->
    {neg};
classify_op(ld64_imm) ->
    {ld64};
classify_op(ld_map_fd) ->
    {ld64};
classify_op(ld_map_value) ->
    {ld64};
classify_op(ldxw) ->
    {ldx};
classify_op(ldxh) ->
    {ldx};
classify_op(ldxb) ->
    {ldx};
classify_op(ldxdw) ->
    {ldx};
classify_op(stxw) ->
    {stx};
classify_op(stxh) ->
    {stx};
classify_op(stxb) ->
    {stx};
classify_op(stxdw) ->
    {stx};
classify_op(stw) ->
    {st_imm};
classify_op(sth) ->
    {st_imm};
classify_op(stb) ->
    {st_imm};
classify_op(stdw) ->
    {st_imm};
%% handled separately
classify_op(ja) ->
    unknown;
classify_op(Op) ->
    Name = atom_to_list(Op),
    case Name of
        "add64_imm" ->
            {alu_imm, add};
        "sub64_imm" ->
            {alu_imm, sub};
        "mul64_imm" ->
            {alu_imm, mul};
        "div64_imm" ->
            {alu_imm, div_op};
        "or64_imm" ->
            {alu_imm, bor_op};
        "and64_imm" ->
            {alu_imm, band_op};
        "lsh64_imm" ->
            {alu_imm, lsh};
        "rsh64_imm" ->
            {alu_imm, rsh};
        "mod64_imm" ->
            {alu_imm, mod};
        "xor64_imm" ->
            {alu_imm, xor_op};
        "arsh64_imm" ->
            {alu_imm, arsh};
        "add32_imm" ->
            {alu_imm, add};
        "sub32_imm" ->
            {alu_imm, sub};
        "mul32_imm" ->
            {alu_imm, mul};
        "div32_imm" ->
            {alu_imm, div_op};
        "or32_imm" ->
            {alu_imm, bor_op};
        "and32_imm" ->
            {alu_imm, band_op};
        "lsh32_imm" ->
            {alu_imm, lsh};
        "rsh32_imm" ->
            {alu_imm, rsh};
        "mod32_imm" ->
            {alu_imm, mod};
        "xor32_imm" ->
            {alu_imm, xor_op};
        "arsh32_imm" ->
            {alu_imm, arsh};
        "add64_reg" ->
            {alu_reg, add};
        "sub64_reg" ->
            {alu_reg, sub};
        "mul64_reg" ->
            {alu_reg, mul};
        "div64_reg" ->
            {alu_reg, div_op};
        "or64_reg" ->
            {alu_reg, bor_op};
        "and64_reg" ->
            {alu_reg, band_op};
        "lsh64_reg" ->
            {alu_reg, lsh};
        "rsh64_reg" ->
            {alu_reg, rsh};
        "mod64_reg" ->
            {alu_reg, mod};
        "xor64_reg" ->
            {alu_reg, xor_op};
        "arsh64_reg" ->
            {alu_reg, arsh};
        "add32_reg" ->
            {alu_reg, add};
        "sub32_reg" ->
            {alu_reg, sub};
        "mul32_reg" ->
            {alu_reg, mul};
        "div32_reg" ->
            {alu_reg, div_op};
        "or32_reg" ->
            {alu_reg, bor_op};
        "and32_reg" ->
            {alu_reg, band_op};
        "lsh32_reg" ->
            {alu_reg, lsh};
        "rsh32_reg" ->
            {alu_reg, rsh};
        "mod32_reg" ->
            {alu_reg, mod};
        "xor32_reg" ->
            {alu_reg, xor_op};
        "arsh32_reg" ->
            {alu_reg, arsh};
        %% Conditional jumps
        "j" ++ Rest ->
            case lists:suffix("_imm", Rest) orelse lists:suffix("32_imm", Rest) of
                true ->
                    {cond_jmp_imm};
                false ->
                    case lists:suffix("_reg", Rest) orelse lists:suffix("32_reg", Rest) of
                        true -> {cond_jmp_reg};
                        false -> unknown
                    end
            end;
        _ ->
            unknown
    end.

%%% ===================================================================
%%% Helper: find second slots of LD_IMM64 instructions
%%% ===================================================================

ld64_second_slots([], _PC, Acc) ->
    Acc;
ld64_second_slots([#vm_insn{op = Op} | Rest], PC, Acc) when
    Op =:= ld64_imm; Op =:= ld_map_fd; Op =:= ld_map_value
->
    %% Next slot (PC+1) is the nop placeholder
    ld64_second_slots(Rest, PC + 1, Acc#{PC + 1 => true});
ld64_second_slots([_ | Rest], PC, Acc) ->
    ld64_second_slots(Rest, PC + 1, Acc).
