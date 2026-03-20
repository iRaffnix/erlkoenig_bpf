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

-module(ebpf_regalloc_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebpf_ir.hrl").

%%% ===================================================================
%%% Helper: Build IR programs for regalloc testing
%%% ===================================================================

%% Build a linear program with N virtual registers, all live from
%% definition to the exit instruction. This forces maximum register
%% pressure since all intervals overlap.
make_linear_program(VRegCount) ->
    %% Create instructions: mov {v,1} = 1, mov {v,2} = 2, ...
    Instrs = [
        #ir_instr{
            op = mov,
            dst = {v, I},
            args = [I],
            type = {scalar, u64},
            loc = undefined
        }
     || I <- lists:seq(1, VRegCount)
    ],
    %% Sum chain: add v_ret = sum of all vregs (forces all to be live until exit)
    SumInstrs =
        case VRegCount of
            0 ->
                [
                    #ir_instr{
                        op = mov,
                        dst = v_ret,
                        args = [0],
                        type = {scalar, u64},
                        loc = undefined
                    }
                ];
            _ ->
                [
                    #ir_instr{
                        op = mov,
                        dst = v_ret,
                        args = [{v, 1}],
                        type = {scalar, u64},
                        loc = undefined
                    }
                ] ++
                    [
                        #ir_instr{
                            op = add,
                            dst = v_ret,
                            args = [v_ret, {v, I}],
                            type = {scalar, u64},
                            loc = undefined
                        }
                     || I <- lists:seq(2, VRegCount)
                    ]
        end,
    Block = #ir_block{
        label = entry,
        instrs = Instrs ++ SumInstrs,
        term = {exit, v_ret}
    },
    #ir_program{
        prog_type = xdp,
        name = <<"regalloc_test">>,
        entry = entry,
        blocks = #{entry => Block},
        next_reg = VRegCount + 1
    }.

%% Build a program with ctx + fp + N user variables (forces pre-coloring).
make_precolor_program(VRegCount) ->
    %% Use v_ctx and v_fp alongside user vregs
    Instrs = [
        #ir_instr{
            op = mov,
            dst = {v, I},
            args = [v_ctx],
            type = {scalar, u64},
            loc = undefined
        }
     || I <- lists:seq(1, VRegCount)
    ],
    SumInstrs =
        case VRegCount of
            0 ->
                [
                    #ir_instr{
                        op = mov,
                        dst = v_ret,
                        args = [v_ctx],
                        type = {scalar, u64},
                        loc = undefined
                    }
                ];
            _ ->
                [
                    #ir_instr{
                        op = mov,
                        dst = v_ret,
                        args = [{v, 1}],
                        type = {scalar, u64},
                        loc = undefined
                    }
                ] ++
                    [
                        #ir_instr{
                            op = add,
                            dst = v_ret,
                            args = [v_ret, {v, I}],
                            type = {scalar, u64},
                            loc = undefined
                        }
                     || I <- lists:seq(2, VRegCount)
                    ]
        end,
    Block = #ir_block{
        label = entry,
        instrs = Instrs ++ SumInstrs,
        term = {exit, v_ret}
    },
    #ir_program{
        prog_type = xdp,
        name = <<"precolor_test">>,
        entry = entry,
        blocks = #{entry => Block},
        next_reg = VRegCount + 1
    }.

%% Build a program with a loop: some variables defined before, used inside.
make_loop_program() ->
    %% Before loop: define {v,1} and {v,2}
    EntryInstrs = [
        #ir_instr{
            op = mov,
            dst = {v, 1},
            args = [10],
            type = {scalar, u64},
            loc = undefined
        },
        #ir_instr{
            op = mov,
            dst = {v, 2},
            args = [20],
            type = {scalar, u64},
            loc = undefined
        },
        #ir_instr{
            op = mov,
            dst = {v, 3},
            args = [5],
            type = {scalar, u64},
            loc = undefined
        }
    ],
    EntryBlock = #ir_block{
        label = entry,
        instrs = EntryInstrs,
        %% header
        term = {br, {label, 1}}
    },
    %% Header: check {v,3} != 0
    HeaderBlock = #ir_block{
        label = {label, 1},
        instrs = [],
        term = {cond_br, {v, 3}, {label, 2}, {label, 3}}
    },
    %% Body: use {v,1} and {v,2}, decrement {v,3}
    BodyInstrs = [
        #ir_instr{
            op = add,
            dst = {v, 1},
            args = [{v, 1}, {v, 2}],
            type = {scalar, u64},
            loc = undefined
        },
        #ir_instr{
            op = sub,
            dst = {v, 3},
            args = [{v, 3}, 1],
            type = {scalar, u64},
            loc = undefined
        }
    ],
    BodyBlock = #ir_block{
        label = {label, 2},
        instrs = BodyInstrs,
        %% back-edge
        term = {br, {label, 1}}
    },
    %% Exit: return {v,1}
    ExitBlock = #ir_block{
        label = {label, 3},
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [{v, 1}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    #ir_program{
        prog_type = xdp,
        name = <<"loop_test">>,
        entry = entry,
        blocks = #{
            entry => EntryBlock,
            {label, 1} => HeaderBlock,
            {label, 2} => BodyBlock,
            {label, 3} => ExitBlock
        },
        next_reg = 4
    }.

%% Build a program with sequential (non-overlapping) variable lifetimes.
make_sequential_program(VRegCount) ->
    %% Each variable is defined, used once, then never again.
    %% This should reuse registers aggressively.
    Instrs = lists:flatmap(
        fun(I) ->
            [
                #ir_instr{
                    op = mov,
                    dst = {v, I},
                    args = [I],
                    type = {scalar, u64},
                    loc = undefined
                },
                #ir_instr{
                    op = add,
                    dst = v_ret,
                    args = [v_ret, {v, I}],
                    type = {scalar, u64},
                    loc = undefined
                }
            ]
        end,
        lists:seq(1, VRegCount)
    ),
    InitInstr = #ir_instr{
        op = mov,
        dst = v_ret,
        args = [0],
        type = {scalar, u64},
        loc = undefined
    },
    Block = #ir_block{
        label = entry,
        instrs = [InitInstr | Instrs],
        term = {exit, v_ret}
    },
    #ir_program{
        prog_type = xdp,
        name = <<"seq_test">>,
        entry = entry,
        blocks = #{entry => Block},
        next_reg = VRegCount + 1
    }.

%%% ===================================================================
%%% Trivial allocation: few variables, no spills
%%% ===================================================================

single_variable_test() ->
    Prog = make_linear_program(1),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    %% v_ret must be assigned R0
    ?assertEqual(0, maps:get(v_ret, Assign)),
    %% {v,1} must get a physical register
    ?assert(is_integer(maps:get({v, 1}, Assign))).

two_variables_test() ->
    Prog = make_linear_program(2),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    R1 = maps:get({v, 1}, Assign),
    R2 = maps:get({v, 2}, Assign),
    %% Different registers
    ?assertNotEqual(R1, R2),
    %% Neither may be R0 (v_ret) since they're live alongside v_ret
    ?assertNotEqual(R1, maps:get(v_ret, Assign)),
    ?assertNotEqual(R2, maps:get(v_ret, Assign)).

zero_variables_test() ->
    Prog = make_linear_program(0),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    ?assertEqual(0, maps:get(v_ret, Assign)).

%%% ===================================================================
%%% Pre-coloring: v_ctx → R6, v_ret → R0, v_fp → R10
%%% ===================================================================

precolor_ctx_r6_test() ->
    Prog = make_precolor_program(1),
    {Assign, _} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(6, maps:get(v_ctx, Assign)),
    ?assertEqual(0, maps:get(v_ret, Assign)).

precolor_fp_r10_test() ->
    %% Build a program that uses v_fp (stack access)
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = add,
                dst = {v, 1},
                args = [v_fp, -8],
                type = {ptr, stack},
                loc = undefined
            },
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [{v, 1}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"fp_test">>,
        entry = entry,
        blocks = #{entry => Block},
        next_reg = 2
    },
    {Assign, _} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(10, maps:get(v_fp, Assign)),
    ?assertEqual(0, maps:get(v_ret, Assign)).

precolored_regs_excluded_from_pool_test() ->
    %% v_ctx at R6 means no other vreg can get R6
    Prog = make_precolor_program(6),
    {Assign, _} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(6, maps:get(v_ctx, Assign)),
    UserRegs = [maps:get({v, I}, Assign) || I <- lists:seq(1, 6)],
    %% No user variable should be assigned R6
    lists:foreach(fun(R) -> ?assertNotEqual(6, R) end, UserRegs),
    %% No user variable should be assigned R0 (v_ret is live)
    lists:foreach(fun(R) -> ?assertNotEqual(0, R) end, UserRegs).

%%% ===================================================================
%%% No register collisions (core invariant)
%%% ===================================================================

no_collision_5_vars_test() ->
    assert_no_collisions(5).

no_collision_7_vars_test() ->
    assert_no_collisions(7).

assert_no_collisions(N) ->
    Prog = make_linear_program(N),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    %% All non-spilled variables live at the same time must have distinct pregs
    NonSpilled = maps:without(maps:keys(Spills), Assign),
    Regs = maps:values(NonSpilled),
    ?assertEqual(length(Regs), length(lists:usort(Regs))).

%%% ===================================================================
%%% Spill behavior: more variables than registers
%%% ===================================================================

spill_when_exceeding_registers_test() ->
    %% 8 available physical regs (R1-R5, R7-R9) plus R0 (v_ret) = 9 total
    %% but v_ret takes R0, leaving 8. With > 8 simultaneous live vregs,
    %% spills must occur (and R5 reserved as scratch → 7 available).
    Prog = make_linear_program(10),
    {_Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assert(maps:size(Spills) > 0).

spill_offsets_are_negative_multiples_of_8_test() ->
    Prog = make_linear_program(12),
    {_Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assert(maps:size(Spills) > 0),
    maps:foreach(
        fun(_VReg, Offset) ->
            ?assert(Offset < 0),
            ?assertEqual(0, Offset rem 8)
        end,
        Spills
    ).

spill_offsets_are_unique_test() ->
    Prog = make_linear_program(12),
    {_Assign, Spills} = ebpf_regalloc:allocate(Prog),
    Offsets = maps:values(Spills),
    ?assertEqual(length(Offsets), length(lists:usort(Offsets))).

r5_reserved_as_scratch_when_spills_test() ->
    %% When spills happen, R5 must NOT be assigned to any variable
    %% (it's reserved as scratch for loading spilled values)
    Prog = make_linear_program(12),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assert(maps:size(Spills) > 0),
    AssignedRegs = maps:values(Assign),
    ?assertNot(lists:member(5, AssignedRegs)).

no_spill_for_sequential_variables_test() ->
    %% 20 variables with non-overlapping lifetimes → registers should be reused
    Prog = make_sequential_program(20),
    {_Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)).

%%% ===================================================================
%%% Loop interval extension
%%% ===================================================================

loop_extends_intervals_test() ->
    %% Variables defined before loop but used inside must survive
    %% across the entire loop body (back-edge extends the interval).
    Prog = make_loop_program(),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    %% All 3 user vregs + v_ret must have distinct registers
    R1 = maps:get({v, 1}, Assign),
    R2 = maps:get({v, 2}, Assign),
    R3 = maps:get({v, 3}, Assign),
    RRet = maps:get(v_ret, Assign),
    AllRegs = [R1, R2, R3, RRet],
    ?assertEqual(4, length(lists:usort(AllRegs))).

%%% ===================================================================
%%% Regression: nested-loop spill scenario
%%% ===================================================================

%% The nested-loop spill conflict (fixed 2026-03-11) happened when:
%% - Both Dst and a 2nd Arg were spilled
%% - Both needed R5 as scratch for load/store
%% We test this by creating enough pressure for spills with overlapping
%% lifetimes, then verify the allocation is still consistent.
many_overlapping_variables_test() ->
    Prog = make_linear_program(15),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    %% Total assigned + spilled must cover all vregs
    TotalVRegs = [{v, I} || I <- lists:seq(1, 15)] ++ [v_ret],
    lists:foreach(
        fun(VR) ->
            InAssign = maps:is_key(VR, Assign),
            InSpill = maps:is_key(VR, Spills),
            ?assert(InAssign orelse InSpill)
        end,
        TotalVRegs
    ).

%%% ===================================================================
%%% Edge cases
%%% ===================================================================

%% Only pre-colored registers, no user variables
only_precolored_test() ->
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [v_ctx],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"only_pre">>,
        entry = entry,
        blocks = #{entry => Block},
        next_reg = 1
    },
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    ?assertEqual(0, maps:get(v_ret, Assign)),
    ?assertEqual(6, maps:get(v_ctx, Assign)).

%% Two blocks with disjoint variable usage
two_block_disjoint_test() ->
    Block1 = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = mov,
                dst = {v, 1},
                args = [42],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {br, {label, 1}}
    },
    Block2 = #ir_block{
        label = {label, 1},
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [{v, 1}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"two_block">>,
        entry = entry,
        blocks = #{entry => Block1, {label, 1} => Block2},
        next_reg = 2
    },
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    ?assert(maps:is_key({v, 1}, Assign)),
    ?assertEqual(0, maps:get(v_ret, Assign)).

%% Conditional branch with variables used in both sides
diamond_cfg_test() ->
    Entry = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = mov,
                dst = {v, 1},
                args = [1],
                type = {scalar, u64},
                loc = undefined
            },
            #ir_instr{
                op = mov,
                dst = {v, 2},
                args = [2],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {cond_br, {v, 1}, {label, 1}, {label, 2}}
    },
    TrueBlock = #ir_block{
        label = {label, 1},
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [{v, 1}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    FalseBlock = #ir_block{
        label = {label, 2},
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [{v, 2}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"diamond">>,
        entry = entry,
        blocks = #{
            entry => Entry,
            {label, 1} => TrueBlock,
            {label, 2} => FalseBlock
        },
        next_reg = 3
    },
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    ?assertEqual(0, maps:size(Spills)),
    ?assertNotEqual(maps:get({v, 1}, Assign), maps:get({v, 2}, Assign)).

%%% ===================================================================
%%% Stress: maximum register pressure
%%% ===================================================================

%% 20 simultaneous live variables — must handle gracefully
stress_20_vars_test() ->
    Prog = make_linear_program(20),
    {Assign, Spills} = ebpf_regalloc:allocate(Prog),
    %% Must not crash and must account for all vregs
    TotalVRegs = [{v, I} || I <- lists:seq(1, 20)] ++ [v_ret],
    lists:foreach(
        fun(VR) ->
            ?assert(maps:is_key(VR, Assign) orelse maps:is_key(VR, Spills))
        end,
        TotalVRegs
    ),
    %% Among non-spilled, all assigned registers must be distinct
    NonSpilled = maps:without(maps:keys(Spills), Assign),
    Regs = maps:values(NonSpilled),
    ?assertEqual(length(Regs), length(lists:usort(Regs))).
