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

-module(ebpf_vm_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebpf_vm.hrl").

%%% ===================================================================
%%% WP-002 Acceptance: mov64_imm(0, 42) + exit → {ok, 42}
%%% ===================================================================

acceptance_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% ALU64 immediate
%%% ===================================================================

add64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 10),
        ebpf_insn:add64_imm(0, 32),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

sub64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 50),
        ebpf_insn:sub64_imm(0, 8),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

mul64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 6),
        ebpf_insn:mul64_imm(0, 7),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

div64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 84),
        ebpf_insn:div64_imm(0, 2),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

mod64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 47),
        ebpf_insn:mod64_imm(0, 5),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 2}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% ALU64 register
%%% ===================================================================

add64_reg_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 20),
        ebpf_insn:mov64_imm(1, 22),
        ebpf_insn:add64_reg(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% ALU32
%%% ===================================================================

mov32_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov32_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

add32_reg_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov32_imm(0, 20),
        ebpf_insn:mov32_imm(1, 22),
        ebpf_insn:add32_reg(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

alu32_mask_test() ->
    %% ALU32 should mask to 32 bits
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#FFFFFFFF),
        ebpf_insn:add32_imm(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 0}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Bitwise operations
%%% ===================================================================

or64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#0A),
        ebpf_insn:or64_imm(0, 16#20),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#2A}, ebpf_vm:run(Prog, #{})).

and64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#FF),
        ebpf_insn:and64_imm(0, 16#2A),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#2A}, ebpf_vm:run(Prog, #{})).

xor64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#FF),
        ebpf_insn:xor64_imm(0, 16#D5),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#2A}, ebpf_vm:run(Prog, #{})).

lsh64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:lsh64_imm(0, 4),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16}, ebpf_vm:run(Prog, #{})).

rsh64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 64),
        ebpf_insn:rsh64_imm(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 32}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Jumps
%%% ===================================================================

ja_test() ->
    Prog = ebpf_insn:assemble([
        %% 0
        ebpf_insn:mov64_imm(0, 1),
        %% 1: skip next
        ebpf_insn:ja(1),
        %% 2: skipped
        ebpf_insn:mov64_imm(0, 99),
        %% 3
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 1}, ebpf_vm:run(Prog, #{})).

jeq_imm_taken_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 10),
        %% if r0==10 skip 1
        ebpf_insn:jeq_imm(0, 10, 1),
        %% skipped
        ebpf_insn:mov64_imm(0, 99),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 10}, ebpf_vm:run(Prog, #{})).

jeq_imm_not_taken_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 10),
        %% not taken
        ebpf_insn:jeq_imm(0, 20, 1),
        %% executed
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

jgt_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 10),
        %% 10 > 5 → taken
        ebpf_insn:jgt_imm(0, 5, 1),
        ebpf_insn:mov64_imm(0, 99),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 10}, ebpf_vm:run(Prog, #{})).

jne_reg_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:mov64_imm(1, 2),
        %% 1 != 2 → taken
        ebpf_insn:jne_reg(0, 1, 1),
        ebpf_insn:mov64_imm(0, 99),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 1}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Loop (add 1 ten times)
%%% ===================================================================

loop_test() ->
    Prog = ebpf_insn:assemble([
        %% 0: r0 = 0 (sum)
        ebpf_insn:mov64_imm(0, 0),
        %% 1: r1 = 10 (counter)
        ebpf_insn:mov64_imm(1, 10),
        %% 2: r0 += 1
        ebpf_insn:add64_imm(0, 1),
        %% 3: r1 -= 1
        ebpf_insn:sub64_imm(1, 1),
        %% 4: if r1 > 0, goto 2
        ebpf_insn:jgt_imm(1, 0, -3),
        %% 5
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 10}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% LD64_IMM
%%% ===================================================================

ld64_imm_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#DEADBEEF),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#DEADBEEF}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Memory (stack)
%%% ===================================================================

stack_store_load_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 42),
        %% *(r10-4) = r1
        ebpf_insn:stxw(10, -4, 1),
        %% r0 = *(r10-4)
        ebpf_insn:ldxw(0, 10, -4),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 42}, ebpf_vm:run(Prog, #{})).

stack_byte_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(1, 255),
        ebpf_insn:stxb(10, -1, 1),
        ebpf_insn:ldxb(0, 10, -1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 255}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Helper call
%%% ===================================================================

helper_ktime_test() ->
    Prog = ebpf_insn:assemble([
        %% ktime_get_ns (helper 5)
        ebpf_insn:call(5),
        ebpf_insn:exit_insn()
    ]),
    {ok, Val} = ebpf_vm:run(Prog, #{}),
    ?assert(is_integer(Val)),
    ?assert(Val > 0 orelse Val =:= 0).

helper_cpu_id_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:call(14),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 0}, ebpf_vm:run(Prog, #{})).

unknown_helper_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:call(9999),
        ebpf_insn:exit_insn()
    ]),
    ?assertMatch({error, {helper_error, 9999, _}}, ebpf_vm:run(Prog, #{})).

%%% ===================================================================
%%% Instruction limit
%%% ===================================================================

insn_limit_test() ->
    %% Infinite loop — should hit limit
    Prog = ebpf_insn:assemble([
        %% loop forever
        ebpf_insn:ja(-1)
    ]),
    ?assertEqual(
        {error, insn_limit_exceeded},
        ebpf_vm:run(Prog, #{}, #{insn_limit => 100})
    ).

%%% ===================================================================
%%% Decode
%%% ===================================================================

decode_program_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    Insns = ebpf_vm_decode:decode_program(Prog),
    ?assertEqual(2, array:size(Insns)),
    ?assertMatch(#vm_insn{op = mov64_imm, dst = 0, imm = 42}, array:get(0, Insns)),
    ?assertMatch(#vm_insn{op = exit_insn}, array:get(1, Insns)).

%%% ===================================================================
%%% ALU module directly
%%% ===================================================================

alu_div_zero_test() ->
    ?assertEqual(0, ebpf_vm_alu:exec('div', 42, 0, 64)).

alu_mod_zero_test() ->
    ?assertEqual(0, ebpf_vm_alu:exec(mod, 42, 0, 64)).

%%% ===================================================================
%%% JMP module directly
%%% ===================================================================

jmp_signed_test() ->
    %% -1 as u64 > 5 unsigned, but < 5 signed
    Neg1_64 = 16#FFFFFFFFFFFFFFFF,
    ?assertEqual(true, ebpf_vm_jmp:eval(jgt, Neg1_64, 5, 64)),
    ?assertEqual(false, ebpf_vm_jmp:eval(jsgt, Neg1_64, 5, 64)).

%%% ===================================================================
%%% Memory module directly
%%% ===================================================================

mem_oob_test() ->
    Stack = <<0:(?VM_STACK_SIZE * 8)>>,
    %% Bad address
    ?assertEqual({error, bad_addr}, ebpf_vm_mem:read(#{}, 0, 4, Stack)).

mem_stack_oob_test() ->
    Stack = <<0:(?VM_STACK_SIZE * 8)>>,
    %% Beyond stack region → bad_addr (address outside any known region)
    ?assertEqual(
        {error, bad_addr},
        ebpf_vm_mem:read(#{}, ?VM_STACK_BASE + ?VM_STACK_SIZE, 4, Stack)
    ).

mem_stack_within_bounds_oob_test() ->
    Stack = <<0:(?VM_STACK_SIZE * 8)>>,
    %% Inside stack region but read would exceed bounds
    ?assertEqual(
        {error, oob},
        ebpf_vm_mem:read(#{}, ?VM_STACK_BASE + ?VM_STACK_SIZE - 2, 4, Stack)
    ).

%%% ===================================================================
%%% Maps
%%% ===================================================================

maps_crud_test() ->
    {_Fd, Tab, Meta} = ebpf_vm_maps:create(hash, 4, 4, 10),
    Key = <<1, 0, 0, 0>>,
    Val = <<42, 0, 0, 0>>,
    ?assertEqual(none, ebpf_vm_maps:lookup(Tab, Key, Meta)),
    ?assertEqual(ok, ebpf_vm_maps:update(Tab, Key, Val, Meta)),
    ?assertEqual({ok, Val}, ebpf_vm_maps:lookup(Tab, Key, Meta)),
    ?assertEqual(ok, ebpf_vm_maps:delete(Tab, Key, Meta)),
    ?assertEqual(none, ebpf_vm_maps:lookup(Tab, Key, Meta)),
    ebpf_vm_maps:destroy(Tab).

maps_full_test() ->
    {_Fd, Tab, Meta} = ebpf_vm_maps:create(hash, 4, 4, 2),
    ?assertEqual(ok, ebpf_vm_maps:update(Tab, <<1, 0, 0, 0>>, <<1, 0, 0, 0>>, Meta)),
    ?assertEqual(ok, ebpf_vm_maps:update(Tab, <<2, 0, 0, 0>>, <<2, 0, 0, 0>>, Meta)),
    ?assertEqual({error, full}, ebpf_vm_maps:update(Tab, <<3, 0, 0, 0>>, <<3, 0, 0, 0>>, Meta)),
    ebpf_vm_maps:destroy(Tab).

%%% ===================================================================
%%% Bug fixes: arsh32 sign extension + shift mask width (K1, W4)
%%% ===================================================================

%% K1: arsh32(0x80000000, 1) must give 0xC0000000 (sign bit propagated)
arsh32_sign_extend_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#80000000),
        ebpf_insn:arsh32_imm(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#C0000000}, ebpf_vm:run(Prog, #{})).

%% K1: arsh64(0x8000000000000000, 1) must give 0xC000000000000000
arsh64_sign_extend_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#8000000000000000),
        ebpf_insn:arsh64_imm(0, 1),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 16#C000000000000000}, ebpf_vm:run(Prog, #{})).

%% W4: lsh32 with shift >= 32 must use mask 31 (shift 33 -> shift 1)
lsh32_shift_mask_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 1),
        %% 33 band 31 = 1 -> result = 2
        ebpf_insn:lsh32_imm(0, 33),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 2}, ebpf_vm:run(Prog, #{})).

%% W4: rsh32 with shift >= 32 must use mask 31 (shift 33 -> shift 1)
rsh32_shift_mask_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16),
        %% 33 band 31 = 1 -> result = 8
        ebpf_insn:rsh32_imm(0, 33),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual({ok, 8}, ebpf_vm:run(Prog, #{})).
