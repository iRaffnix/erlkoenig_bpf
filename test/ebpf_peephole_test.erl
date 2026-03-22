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

%% @doc Tests for the peephole optimizer.
%%
%% Three optimization patterns:
%%   P1: Redundant mov elimination (mov rX, rX → removed)
%%   P2: Store-load forwarding (stxdw [r10-8], rA; ldxdw rB, [r10-8] → mov rB, rA)
%%   P3: Double store elimination (stxdw [r10-8], rA; stxdw [r10-8], rB → stxdw [r10-8], rB)
%%
%% Tests verify each pattern in isolation and combined, both with and without jumps.
-module(ebpf_peephole_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%% ===================================================================
%%% P1: Redundant mov elimination
%%% ===================================================================

p1_removes_self_mov64_test() ->
    %% mov64_reg r1, r1 should be removed
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        %% redundant
        ebpf_insn:mov64_reg(1, 1),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p1_removes_self_mov32_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:mov32_imm(0, 42),
        %% redundant
        ebpf_insn:mov32_reg(2, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov32_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p1_preserves_real_mov_test() ->
    %% mov64_reg r1, r2 should NOT be removed
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(2, 42),
        ebpf_insn:mov64_reg(1, 2),
        ebpf_insn:mov64_reg(0, 1),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

p1_removes_multiple_self_movs_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 99),
        ebpf_insn:mov64_reg(0, 0),
        ebpf_insn:mov64_reg(1, 1),
        ebpf_insn:mov64_reg(2, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 99),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

%%% ===================================================================
%%% P2: Store-load forwarding
%%% ===================================================================

p2_stxdw_ldxdw_forwarding_test() ->
    %% stxdw [r10-8], r1; ldxdw r2, [r10-8] → mov r2, r1
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:ldxdw(2, 10, -8),
        ebpf_insn:mov64_reg(0, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        %% forwarded
        ebpf_insn:mov64_reg(2, 1),
        ebpf_insn:mov64_reg(0, 2),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p2_stxw_ldxw_forwarding_test() ->
    %% 32-bit store-load
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 7),
        ebpf_insn:stxw(10, -4, 1),
        ebpf_insn:ldxw(3, 10, -4),
        ebpf_insn:mov64_reg(0, 3),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 7),
        ebpf_insn:mov64_reg(3, 1),
        ebpf_insn:mov64_reg(0, 3),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p2_stxh_ldxh_forwarding_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:stxh(10, -2, 1),
        ebpf_insn:ldxh(2, 10, -2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(2, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p2_stxb_ldxb_forwarding_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:stxb(10, -1, 1),
        ebpf_insn:ldxb(2, 10, -1),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(2, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p2_different_offset_no_forward_test() ->
    %% Different offsets → no forwarding
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        %% different offset!
        ebpf_insn:ldxdw(2, 10, -16),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

p2_different_base_no_forward_test() ->
    %% Different base registers → no forwarding
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        %% different base!
        ebpf_insn:ldxdw(2, 9, -8),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

%%% ===================================================================
%%% P3: Double store elimination
%%% ===================================================================

p3_double_store_same_offset_test() ->
    %% Two consecutive stores to same location → first is dead
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        %% overwrites first
        ebpf_insn:stxdw(10, -8, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 2),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

p3_double_store_different_offset_test() ->
    %% Different offsets → both kept
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:stxdw(10, -16, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

p3_double_store_different_size_test() ->
    %% stxw then stxdw to same offset → different sizes, both kept
    Code = ebpf_insn:assemble([
        ebpf_insn:stxw(10, -8, 1),
        ebpf_insn:stxdw(10, -8, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

p3_works_with_jumps_test() ->
    %% P3 is safe even with jumps (1:1 replacement)
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:stxdw(10, -8, 2),
        %% jump present
        ebpf_insn:jeq_imm(2, 0, 1),
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        %% first store eliminated
        ebpf_insn:stxdw(10, -8, 2),
        ebpf_insn:jeq_imm(2, 0, 1),
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

%%% ===================================================================
%%% Jump safety: P1/P2 disabled when jumps present
%%% ===================================================================

p1_disabled_with_jumps_test() ->
    %% Self-mov should NOT be removed when jumps are present
    Code = ebpf_insn:assemble([
        %% would be removed without jumps
        ebpf_insn:mov64_reg(1, 1),
        ebpf_insn:jeq_imm(1, 0, 1),
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    %% Instruction count must be preserved
    ?assertEqual(byte_size(Code), byte_size(Opt)).

p2_disabled_with_jumps_test() ->
    %% Store-load forwarding should NOT happen when jumps are present
    Code = ebpf_insn:assemble([
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:ldxdw(2, 10, -8),
        ebpf_insn:jeq_imm(2, 0, 1),
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    %% Instruction count must be preserved (P2 would remove 1 insn)
    ?assertEqual(byte_size(Code), byte_size(Opt)).

%%% ===================================================================
%%% Combined patterns
%%% ===================================================================

combined_p1_p2_test() ->
    %% P1 + P2 together in a jump-free program
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        %% P1: redundant
        ebpf_insn:mov64_reg(1, 1),
        ebpf_insn:stxdw(10, -8, 1),
        %% P2: forwarded
        ebpf_insn:ldxdw(2, 10, -8),
        ebpf_insn:mov64_reg(0, 2),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Expected = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        %% P2 result
        ebpf_insn:mov64_reg(2, 1),
        ebpf_insn:mov64_reg(0, 2),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(Expected, Opt).

%%% ===================================================================
%%% Correctness: optimized code produces same result
%%% ===================================================================

correctness_p1_execution_test() ->
    %% Verify optimized code runs identically in the VM
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 10),
        %% redundant
        ebpf_insn:mov64_reg(1, 1),
        ebpf_insn:mov64_imm(2, 32),
        %% redundant
        ebpf_insn:mov64_reg(2, 2),
        ebpf_insn:add64_reg(1, 2),
        ebpf_insn:mov64_reg(0, 1),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, OrigResult} = ebpf_vm:run(Code, Ctx),
    {ok, OptResult} = ebpf_vm:run(Opt, Ctx),
    ?assertEqual(42, OrigResult),
    ?assertEqual(OrigResult, OptResult).

correctness_p2_execution_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:ldxdw(0, 10, -8),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, OrigResult} = ebpf_vm:run(Code, Ctx),
    {ok, OptResult} = ebpf_vm:run(Opt, Ctx),
    ?assertEqual(42, OrigResult),
    ?assertEqual(OrigResult, OptResult).

correctness_p3_execution_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 99),
        ebpf_insn:mov64_imm(2, 42),
        %% dead store
        ebpf_insn:stxdw(10, -8, 1),
        %% overwrites
        ebpf_insn:stxdw(10, -8, 2),
        ebpf_insn:ldxdw(0, 10, -8),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, OrigResult} = ebpf_vm:run(Code, Ctx),
    {ok, OptResult} = ebpf_vm:run(Opt, Ctx),
    ?assertEqual(42, OrigResult),
    ?assertEqual(OrigResult, OptResult).

%%% ===================================================================
%%% End-to-end: EBL → compile → optimize → execute
%%% ===================================================================

e2e_peephole_on_off_test() ->
    %% Same program compiled with and without peephole must produce same result
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let a = 10\n"
        "    let b = 20\n"
        "    let c = a + b\n"
        "    let d = c * 2\n"
        "    return d\n"
        "  end\n"
        "end"
    >>,
    {ok, BinOpt} = ebl_compile:compile(Src),
    {ok, BinRaw} = ebl_compile:compile(Src, #{peephole => false}),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, ResultOpt} = ebpf_vm:run(BinOpt, Ctx),
    {ok, ResultRaw} = ebpf_vm:run(BinRaw, Ctx),
    ?assertEqual(60, ResultOpt),
    ?assertEqual(ResultRaw, ResultOpt),
    %% Optimized should be smaller or equal
    ?assert(byte_size(BinOpt) =< byte_size(BinRaw)).

e2e_peephole_with_loop_test() ->
    %% Loop program (has jumps) — peephole should not break it
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let s = 0\n"
        "    for i in 0..5 do\n"
        "      s = s + i\n"
        "    end\n"
        "    return s\n"
        "  end\n"
        "end"
    >>,
    {ok, BinOpt} = ebl_compile:compile(Src),
    {ok, BinRaw} = ebl_compile:compile(Src, #{peephole => false}),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, ResultOpt} = ebpf_vm:run(BinOpt, Ctx),
    {ok, ResultRaw} = ebpf_vm:run(BinRaw, Ctx),
    ?assertEqual(10, ResultOpt),
    ?assertEqual(ResultRaw, ResultOpt).

e2e_peephole_with_conditionals_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let x = 5\n"
        "    if x > 3 do\n"
        "      return x * 10\n"
        "    else\n"
        "      return x\n"
        "    end\n"
        "  end\n"
        "end"
    >>,
    {ok, BinOpt} = ebl_compile:compile(Src),
    {ok, BinRaw} = ebl_compile:compile(Src, #{peephole => false}),
    Ctx = #{ctx => <<0:192>>, packet => <<>>},
    {ok, ResultOpt} = ebpf_vm:run(BinOpt, Ctx),
    {ok, ResultRaw} = ebpf_vm:run(BinRaw, Ctx),
    ?assertEqual(50, ResultOpt),
    ?assertEqual(ResultRaw, ResultOpt).

%%% ===================================================================
%%% Edge cases
%%% ===================================================================

empty_program_test() ->
    Code = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

single_insn_test() ->
    Code = ebpf_insn:assemble([ebpf_insn:exit_insn()]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).

ld_map_fd_not_broken_test() ->
    %% ld_map_fd is 16 bytes — peephole must not misalign it
    Code = ebpf_insn:assemble([
        %% 16-byte insn
        ebpf_insn:ld_map_fd(1, 0),
        ebpf_insn:mov64_reg(0, 1),
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Code),
    ?assertEqual(Code, Opt).
