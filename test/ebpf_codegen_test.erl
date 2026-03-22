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

-module(ebpf_codegen_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebpf_ir.hrl").
-include("ebpf_opcodes.hrl").

%%% ===================================================================
%%% WP-006: v_ctx prolog — mov r6, r1 as first instruction
%%% ===================================================================

%% Verify the first instruction is mov64_reg(6, 1) at the opcode level.
prolog_mov_r6_r1_test() ->
    Prog = make_trivial_program(),
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    %% First 8 bytes = first instruction
    <<First:8/binary, _/binary>> = Bin,
    {Op, Dst, Src, _Off, _Imm} = ebpf_insn:decode(First),
    ?assertEqual(mov64_reg, Op),
    ?assertEqual(6, Dst),
    ?assertEqual(1, Src).

%% Verify raw opcode byte is 0xbf (ALU64 | MOV | X).
prolog_opcode_byte_test() ->
    Prog = make_trivial_program(),
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    <<Opcode:8, _:7/binary, _/binary>> = Bin,
    ?assertEqual(16#bf, Opcode).

%% Verify that v_ctx references use R6 after the prolog.
ctx_survives_helper_call_test() ->
    %% Build a program: call_helper, then use v_ctx, exit.
    %% After codegen the prolog saves R1→R6, so v_ctx (R6) is intact
    %% even though call_helper clobbers R1-R5.
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = v_ret,
                args = [{fn, test_helper}],
                type = {scalar, u64},
                loc = undefined
            },
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
        name = <<"ctx_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    %% First instruction must still be the prolog
    <<First:8/binary, _/binary>> = Bin,
    {Op, Dst, Src, _, _} = ebpf_insn:decode(First),
    ?assertEqual(mov64_reg, Op),
    ?assertEqual(6, Dst),
    ?assertEqual(1, Src),
    %% The mov v_ret, v_ctx should become mov r0, r6 (not r0, r1)
    %% Find it in the bytecode: scan for mov64_reg with dst=0, src=6
    Found = find_insn(Bin, 8, fun(I) ->
        case ebpf_insn:decode(I) of
            {mov64_reg, 0, 6, _, _} -> true;
            _ -> false
        end
    end),
    ?assert(Found).

%% End-to-end: compiled program with ctx still produces correct output.
e2e_prolog_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    return 42\n"
        "  end\n"
        "end"
    >>,
    {ok, Bin} = ebl_compile:compile(Src),
    %% First instruction must be mov r6, r1
    <<First:8/binary, _/binary>> = Bin,
    {Op, Dst, Src2, _, _} = ebpf_insn:decode(First),
    ?assertEqual(mov64_reg, Op),
    ?assertEqual(6, Dst),
    ?assertEqual(1, Src2),
    %% Program still runs correctly
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% WP-007: Helper Call Codegen
%%% ===================================================================

%% Verify ktime_get_ns (0 args) emits call instruction with helper ID 5.
helper_call_ktime_bytecode_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = v_ret,
                args = [{fn, <<"ktime_get_ns">>}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"ktime_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    %% Must contain a call instruction with imm=5
    Found = find_insn(Bin, 0, fun(I) ->
        case ebpf_insn:decode(I) of
            {call, 0, 0, 0, 5} -> true;
            _ -> false
        end
    end),
    ?assert(Found).

%% Verify helper call with arguments loads them into R1-R5.
helper_call_with_args_bytecode_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = mov,
                dst = {v, 1},
                args = [100],
                type = {scalar, u64},
                loc = undefined
            },
            #ir_instr{
                op = call_helper,
                dst = v_ret,
                args = [{fn, <<"map_lookup_elem">>}, {v, 1}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"args_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10, {v, 1} => 7},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    %% Must contain call instruction with imm=1 (map_lookup_elem)
    FoundCall = find_insn(Bin, 0, fun(I) ->
        case ebpf_insn:decode(I) of
            {call, 0, 0, 0, 1} -> true;
            _ -> false
        end
    end),
    ?assert(FoundCall),
    %% Must contain mov r1, r7 (loading arg into R1)
    FoundArgMov = find_insn(Bin, 0, fun(I) ->
        case ebpf_insn:decode(I) of
            {mov64_reg, 1, 7, _, _} -> true;
            _ -> false
        end
    end),
    ?assert(FoundArgMov).

%% Verify result is correctly moved from R0 to destination.
helper_call_result_transfer_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = {v, 1},
                args = [{fn, <<"ktime_get_ns">>}],
                type = {scalar, u64},
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
        name = <<"result_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10, {v, 1} => 7},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    %% Must contain mov r7, r0 (result transfer from R0 to {v,1}=R7)
    Found = find_insn(Bin, 0, fun(I) ->
        case ebpf_insn:decode(I) of
            {mov64_reg, 7, 0, _, _} -> true;
            _ -> false
        end
    end),
    ?assert(Found).

%% VM execution: ktime_get_ns returns a non-zero timestamp.
helper_call_ktime_vm_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = v_ret,
                args = [{fn, <<"ktime_get_ns">>}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"ktime_vm_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assert(is_integer(Result)),
    ?assert(Result > 0).

%% VM execution: get_smp_processor_id returns 0.
helper_call_cpu_id_vm_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = v_ret,
                args = [{fn, <<"get_smp_processor_id">>}],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"cpuid_vm_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

%% Helper call result used in computation.
helper_call_result_used_test() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = call_helper,
                dst = {v, 1},
                args = [{fn, <<"get_smp_processor_id">>}],
                type = {scalar, u64},
                loc = undefined
            },
            %% Add 42 to the result (0 + 42 = 42)
            #ir_instr{
                op = add,
                dst = v_ret,
                args = [{v, 1}, 42],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    Prog = #ir_program{
        prog_type = xdp,
        name = <<"result_used_test">>,
        entry = Entry,
        blocks = #{entry => Block}
    },
    RegMap = #{v_ret => 0, v_ctx => 6, v_fp => 10, {v, 1} => 7},
    Bin = ebpf_codegen:codegen(Prog, RegMap),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

make_trivial_program() ->
    Entry = entry,
    Block = #ir_block{
        label = entry,
        instrs = [
            #ir_instr{
                op = mov,
                dst = v_ret,
                args = [0],
                type = {scalar, u64},
                loc = undefined
            }
        ],
        term = {exit, v_ret}
    },
    #ir_program{
        prog_type = xdp,
        name = <<"test">>,
        entry = Entry,
        blocks = #{entry => Block}
    }.

find_insn(Bin, Pos, _Pred) when Pos >= byte_size(Bin) -> false;
find_insn(Bin, Pos, Pred) ->
    <<_:Pos/binary, Insn:8/binary, _/binary>> = Bin,
    case Pred(Insn) of
        true -> true;
        false -> find_insn(Bin, Pos + 8, Pred)
    end.
