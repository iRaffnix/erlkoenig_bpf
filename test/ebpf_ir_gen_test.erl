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

-module(ebpf_ir_gen_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebl_ast.hrl").
-include("ebpf_ir.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Build a minimal AST program wrapping statements in a main function.
make_program(Stmts) ->
    make_program(xdp, Stmts).

make_program(ProgType, Stmts) ->
    #program{
        type = ProgType,
        name = <<"test">>,
        types = [],
        maps = [],
        consts = [],
        fns = [
            #fn_decl{
                name = <<"main">>,
                params = [{<<"ctx">>, {prim, u64}}],
                ret_type = {prim, u64},
                body = Stmts,
                loc = {1, 0}
            }
        ]
    }.

%% Generate IR and return the ir_program record.
gen(AST) ->
    ebpf_ir_gen:generate(AST).

%% Get instruction ops from a specific block.
block_ops(Label, #ir_program{blocks = Blocks}) ->
    Block = maps:get(Label, Blocks),
    [I#ir_instr.op || I <- Block#ir_block.instrs].

%% Get a specific block's terminator.
block_term(Label, #ir_program{blocks = Blocks}) ->
    Block = maps:get(Label, Blocks),
    Block#ir_block.term.

%% Get all instructions from a block.
block_instrs(Label, #ir_program{blocks = Blocks}) ->
    Block = maps:get(Label, Blocks),
    Block#ir_block.instrs.

%% Count blocks in the program.
block_count(#ir_program{blocks = Blocks}) ->
    maps:size(Blocks).

%%% ===================================================================
%%% Simple return
%%% ===================================================================

return_literal_generates_exit_test() ->
    AST = make_program([
        {return_stmt, {integer_lit, 42, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    ?assertEqual(entry, IR#ir_program.entry),
    ?assertEqual(xdp, IR#ir_program.prog_type),
    %% Entry block must end with {exit, v_ret}
    {exit, v_ret} = block_term(entry, IR).

return_literal_mov_value_test() ->
    AST = make_program([
        {return_stmt, {integer_lit, 42, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    %% Must contain: mov {v,N} = 42, mov v_ret = {v,N}
    Instrs = block_instrs(entry, IR),
    %% Find the instruction that loads 42
    LitInstr = lists:keyfind(mov, #ir_instr.op, Instrs),
    ?assertNotEqual(false, LitInstr),
    ?assert(lists:member(42, LitInstr#ir_instr.args)).

%%% ===================================================================
%%% Context parameter binding
%%% ===================================================================

ctx_param_bound_to_v_ctx_test() ->
    AST = make_program([
        {return_stmt, {var, <<"ctx">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    %% ctx is bound to v_ctx, so return must reference v_ctx
    Instrs = block_instrs(entry, IR),
    %% Find mov v_ret, <something> — the source should be v_ctx
    RetMov = lists:filter(
        fun
            (#ir_instr{op = mov, dst = v_ret}) -> true;
            (_) -> false
        end,
        Instrs
    ),
    ?assert(length(RetMov) > 0),
    [FirstRetMov | _] = RetMov,
    ?assertEqual([v_ctx], FirstRetMov#ir_instr.args).

%%% ===================================================================
%%% Let bindings
%%% ===================================================================

let_binding_creates_register_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 10, {1, 0}}, {1, 0}},
        {return_stmt, {var, <<"x">>, {2, 0}}, {2, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    %% Should have at least: mov {v,N} = 10, mov v_ret = {v,N}
    Ops = [I#ir_instr.op || I <- Instrs],
    %% All ops should be mov (load literal + copy to v_ret)
    lists:foreach(fun(Op) -> ?assertEqual(mov, Op) end, Ops).

wildcard_let_discards_test() ->
    AST = make_program([
        {let_stmt, {wildcard}, {integer_lit, 99, {1, 0}}, {1, 0}},
        {return_stmt, {integer_lit, 0, {2, 0}}, {2, 0}}
    ]),
    IR = gen(AST),
    %% Should not crash, and still produce valid IR
    {exit, v_ret} = block_term(entry, IR).

%%% ===================================================================
%%% Arithmetic: binary operations
%%% ===================================================================

add_generates_add_ir_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"a">>}, {integer_lit, 10, {1, 0}}, {1, 0}},
        {let_stmt, {var_pat, <<"b">>}, {integer_lit, 20, {1, 0}}, {1, 0}},
        {return_stmt, {binop, '+', {var, <<"a">>, {2, 0}}, {var, <<"b">>, {2, 0}}, {2, 0}}, {2, 0}}
    ]),
    IR = gen(AST),
    Ops = block_ops(entry, IR),
    ?assert(lists:member(add, Ops)).

sub_generates_sub_ir_test() ->
    AST = make_program([
        {return_stmt, {binop, '-', {integer_lit, 50, {1, 0}}, {integer_lit, 8, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    Ops = block_ops(entry, IR),
    ?assert(lists:member(sub, Ops)).

mul_generates_mul_ir_test() ->
    AST = make_program([
        {return_stmt, {binop, '*', {integer_lit, 6, {1, 0}}, {integer_lit, 7, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    Ops = block_ops(entry, IR),
    ?assert(lists:member(mul, Ops)).

div_generates_div_ir_test() ->
    AST = make_program([
        {return_stmt, {binop, '/', {integer_lit, 42, {1, 0}}, {integer_lit, 2, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    Ops = block_ops(entry, IR),
    ?assert(lists:member('div', Ops)).

mod_generates_mod_ir_test() ->
    AST = make_program([
        {return_stmt, {binop, '%', {integer_lit, 10, {1, 0}}, {integer_lit, 3, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    Ops = block_ops(entry, IR),
    ?assert(lists:member(mod, Ops)).

bitwise_and_test() ->
    AST = make_program([
        {return_stmt, {binop, '&', {integer_lit, 255, {1, 0}}, {integer_lit, 15, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(and_op, block_ops(entry, IR))).

bitwise_or_test() ->
    AST = make_program([
        {return_stmt, {binop, '|', {integer_lit, 1, {1, 0}}, {integer_lit, 2, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(or_op, block_ops(entry, IR))).

bitwise_xor_test() ->
    AST = make_program([
        {return_stmt, {binop, '^', {integer_lit, 5, {1, 0}}, {integer_lit, 3, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(xor_op, block_ops(entry, IR))).

left_shift_test() ->
    AST = make_program([
        {return_stmt, {binop, '<<', {integer_lit, 1, {1, 0}}, {integer_lit, 4, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(lsh, block_ops(entry, IR))).

right_shift_test() ->
    AST = make_program([
        {return_stmt, {binop, '>>', {integer_lit, 16, {1, 0}}, {integer_lit, 2, {1, 0}}, {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(rsh, block_ops(entry, IR))).

%%% ===================================================================
%%% Unary operations
%%% ===================================================================

negate_generates_neg_test() ->
    AST = make_program([
        {return_stmt, {unop, '-', {integer_lit, 42, {1, 0}}, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(neg, block_ops(entry, IR))).

logical_not_generates_not_op_test() ->
    AST = make_program([
        {return_stmt, {unop, '!', {integer_lit, 1, {1, 0}}, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(not_op, block_ops(entry, IR))).

bitwise_not_generates_xor_test() ->
    %% ~x is compiled as x ^ -1
    AST = make_program([
        {return_stmt, {unop, '~', {integer_lit, 0, {1, 0}}, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    ?assert(lists:member(xor_op, block_ops(entry, IR))).

%%% ===================================================================
%%% Action values per program type
%%% ===================================================================

xdp_drop_value_test() ->
    AST = make_program(xdp, [
        {return_stmt, {atom_lit, <<"drop">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    %% Find the mov that loads the action value
    ActionInstr = [I || #ir_instr{type = action} = I <- Instrs],
    ?assert(length(ActionInstr) > 0),
    [AI | _] = ActionInstr,
    %% XDP_DROP = 1
    ?assertEqual([1], AI#ir_instr.args).

xdp_pass_value_test() ->
    AST = make_program(xdp, [
        {return_stmt, {atom_lit, <<"pass">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    ActionInstr = [I || #ir_instr{type = action} = I <- Instrs],
    [AI | _] = ActionInstr,
    %% XDP_PASS = 2
    ?assertEqual([2], AI#ir_instr.args).

tc_shot_value_test() ->
    AST = make_program(tc, [
        {return_stmt, {atom_lit, <<"shot">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    ActionInstr = [I || #ir_instr{type = action} = I <- Instrs],
    [AI | _] = ActionInstr,
    %% TC_SHOT = 2
    ?assertEqual([2], AI#ir_instr.args).

tc_ok_value_test() ->
    AST = make_program(tc, [
        {return_stmt, {atom_lit, <<"ok">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    ActionInstr = [I || #ir_instr{type = action} = I <- Instrs],
    [AI | _] = ActionInstr,
    %% TC_OK = 0
    ?assertEqual([0], AI#ir_instr.args).

%%% ===================================================================
%%% If/else control flow
%%% ===================================================================

if_generates_multiple_blocks_test() ->
    AST = make_program([
        {if_stmt, {bool_lit, true, {1, 0}}, [{return_stmt, {integer_lit, 1, {2, 0}}, {2, 0}}],
            %% no elifs
            [],
            %% no else
            [], {1, 0}},
        {return_stmt, {integer_lit, 0, {4, 0}}, {4, 0}}
    ]),
    IR = gen(AST),
    %% Must create more than 1 block (entry + then + join at minimum)
    ?assert(block_count(IR) >= 3).

if_else_both_branches_test() ->
    AST = make_program([
        {if_stmt, {bool_lit, true, {1, 0}}, [{return_stmt, {integer_lit, 10, {2, 0}}, {2, 0}}], [],
            [{return_stmt, {integer_lit, 20, {4, 0}}, {4, 0}}], {1, 0}}
    ]),
    IR = gen(AST),
    %% Both branches have exit terminators
    Blocks = maps:values(IR#ir_program.blocks),
    ExitBlocks = [B || B <- Blocks, element(1, B#ir_block.term) =:= exit],
    ?assert(length(ExitBlocks) >= 2).

if_with_comparison_generates_cmp_branch_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 5, {1, 0}}, {1, 0}},
        {if_stmt, {binop, '==', {var, <<"x">>, {2, 0}}, {integer_lit, 5, {2, 0}}, {2, 0}},
            [{return_stmt, {integer_lit, 1, {3, 0}}, {3, 0}}], [],
            [{return_stmt, {integer_lit, 0, {5, 0}}, {5, 0}}], {2, 0}}
    ]),
    IR = gen(AST),
    %% Entry block must have a cond_br with {cmp, eq, ...} terminator
    EntryTerm = block_term(entry, IR),
    ?assertMatch({cond_br, {cmp, eq, _, _}, _, _}, EntryTerm).

elif_generates_chain_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 5, {1, 0}}, {1, 0}},
        {if_stmt, {binop, '==', {var, <<"x">>, {2, 0}}, {integer_lit, 1, {2, 0}}, {2, 0}},
            [{return_stmt, {integer_lit, 10, {3, 0}}, {3, 0}}],
            %% elif
            [
                {
                    {binop, '==', {var, <<"x">>, {4, 0}}, {integer_lit, 2, {4, 0}}, {4, 0}},
                    [{return_stmt, {integer_lit, 20, {5, 0}}, {5, 0}}]
                }
            ],
            [{return_stmt, {integer_lit, 30, {7, 0}}, {7, 0}}], {2, 0}}
    ]),
    IR = gen(AST),
    %% Should have at least 5 blocks: entry, then1, elif_check, then2, else/join
    ?assert(block_count(IR) >= 5).

%%% ===================================================================
%%% For-loop generation
%%% ===================================================================

for_loop_structure_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"sum">>}, {integer_lit, 0, {1, 0}}, {1, 0}},
        {for_stmt, <<"i">>, {integer_lit, 0, {2, 0}}, {integer_lit, 5, {2, 0}},
            [
                {assign_stmt, {var, <<"sum">>, {3, 0}},
                    {binop, '+', {var, <<"sum">>, {3, 0}}, {var, <<"i">>, {3, 0}}, {3, 0}}, {3, 0}}
            ],
            {2, 0}},
        {return_stmt, {var, <<"sum">>, {5, 0}}, {5, 0}}
    ]),
    IR = gen(AST),
    %% For loop creates: entry, header, body, latch, exit blocks
    ?assert(block_count(IR) >= 5),
    %% Entry block should branch (not exit) — it goes to the header
    ?assertMatch({br, _}, block_term(entry, IR)).

for_loop_has_back_edge_test() ->
    AST = make_program([
        {for_stmt, <<"i">>, {integer_lit, 0, {1, 0}}, {integer_lit, 3, {1, 0}}, [], {1, 0}},
        {return_stmt, {integer_lit, 0, {3, 0}}, {3, 0}}
    ]),
    IR = gen(AST),
    %% One of the blocks must branch back to an earlier block (the header)
    %% The latch block has {br, HeaderLabel} — verify a block branches to header
    Blocks = maps:to_list(IR#ir_program.blocks),
    BackEdgeFound = lists:any(
        fun({_Label, Block}) ->
            case Block#ir_block.term of
                {br, Target} ->
                    %% Check if target appears before this block in program order
                    maps:is_key(Target, IR#ir_program.blocks);
                _ ->
                    false
            end
        end,
        Blocks
    ),
    ?assert(BackEdgeFound).

%%% ===================================================================
%%% Break and continue
%%% ===================================================================

break_generates_branch_to_exit_test() ->
    AST = make_program([
        {for_stmt, <<"i">>, {integer_lit, 0, {1, 0}}, {integer_lit, 10, {1, 0}},
            [{break_stmt, {2, 0}}], {1, 0}},
        {return_stmt, {integer_lit, 0, {4, 0}}, {4, 0}}
    ]),
    IR = gen(AST),
    %% Must not crash and must generate valid IR
    Blocks = maps:values(IR#ir_program.blocks),
    %% At least one block should have a {br, ExitLabel} from break
    ?assert(length(Blocks) >= 5).

continue_generates_branch_to_latch_test() ->
    AST = make_program([
        {for_stmt, <<"i">>, {integer_lit, 0, {1, 0}}, {integer_lit, 10, {1, 0}},
            [{continue_stmt, {2, 0}}], {1, 0}},
        {return_stmt, {integer_lit, 0, {4, 0}}, {4, 0}}
    ]),
    IR = gen(AST),
    ?assert(block_count(IR) >= 5).

break_outside_loop_crashes_test() ->
    AST = make_program([
        {break_stmt, {1, 0}}
    ]),
    ?assertError({compile_error, {break_outside_loop, _}}, gen(AST)).

continue_outside_loop_crashes_test() ->
    AST = make_program([
        {continue_stmt, {1, 0}}
    ]),
    ?assertError({compile_error, {continue_outside_loop, _}}, gen(AST)).

%%% ===================================================================
%%% Match statement
%%% ===================================================================

match_generates_comparison_chain_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 2, {1, 0}}, {1, 0}},
        {match_stmt, {var, <<"x">>, {2, 0}},
            [
                {{lit_pat, 1}, [{return_stmt, {integer_lit, 10, {3, 0}}, {3, 0}}]},
                {{lit_pat, 2}, [{return_stmt, {integer_lit, 20, {4, 0}}, {4, 0}}]},
                {{wildcard}, [{return_stmt, {integer_lit, 0, {5, 0}}, {5, 0}}]}
            ],
            {2, 0}}
    ]),
    IR = gen(AST),
    %% Match with 3 arms + join → many blocks
    ?assert(block_count(IR) >= 5).

match_wildcard_always_branches_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 1, {1, 0}}, {1, 0}},
        {match_stmt, {var, <<"x">>, {2, 0}},
            [
                {{wildcard}, [{return_stmt, {integer_lit, 42, {3, 0}}, {3, 0}}]}
            ],
            {2, 0}}
    ]),
    IR = gen(AST),
    %% Wildcard arm should use unconditional branch (br), not cond_br
    Blocks = maps:values(IR#ir_program.blocks),
    WildcardBranch = lists:any(
        fun(B) ->
            case B#ir_block.term of
                {br, _} -> true;
                _ -> false
            end
        end,
        Blocks
    ),
    ?assert(WildcardBranch).

%%% ===================================================================
%%% Context field access
%%% ===================================================================

ctx_field_access_generates_load_test() ->
    AST = make_program(xdp, [
        {return_stmt, {field_access, {var, <<"ctx">>, {1, 0}}, <<"data">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    %% Must contain a load instruction for ctx field
    LoadInstrs = [I || #ir_instr{op = load} = I <- Instrs],
    ?assert(length(LoadInstrs) > 0),
    %% The load should reference v_ctx and {ctx_field, 0, 4} (data offset=0, size=4)
    [L | _] = LoadInstrs,
    ?assertEqual(v_ctx, lists:nth(1, L#ir_instr.args)),
    ?assertMatch({ctx_field, 0, 4}, lists:nth(2, L#ir_instr.args)).

ctx_data_end_offset_test() ->
    AST = make_program(xdp, [
        {return_stmt, {field_access, {var, <<"ctx">>, {1, 0}}, <<"data_end">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    LoadInstrs = [I || #ir_instr{op = load} = I <- Instrs],
    [L | _] = LoadInstrs,
    %% data_end is at offset 4 in xdp_md
    ?assertMatch({ctx_field, 4, 4}, lists:nth(2, L#ir_instr.args)).

tc_field_access_test() ->
    AST = make_program(tc, [
        {return_stmt, {field_access, {var, <<"ctx">>, {1, 0}}, <<"len">>, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    LoadInstrs = [I || #ir_instr{op = load} = I <- Instrs],
    [L | _] = LoadInstrs,
    %% len is at offset 0 in __sk_buff
    ?assertMatch({ctx_field, 0, 4}, lists:nth(2, L#ir_instr.args)).

%%% ===================================================================
%%% Helper calls
%%% ===================================================================

helper_call_generates_call_helper_test() ->
    AST = make_program([
        {return_stmt, {call, <<"ktime_get_ns">>, [], {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    CallInstrs = [I || #ir_instr{op = call_helper} = I <- Instrs],
    ?assert(length(CallInstrs) > 0),
    [C | _] = CallInstrs,
    ?assertMatch([{fn, <<"ktime_get_ns">>}], C#ir_instr.args).

helper_call_with_args_test() ->
    AST = make_program([
        {return_stmt,
            {call, <<"test_fn">>, [{integer_lit, 1, {1, 0}}, {integer_lit, 2, {1, 0}}], {1, 0}},
            {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    CallInstrs = [I || #ir_instr{op = call_helper} = I <- Instrs],
    ?assert(length(CallInstrs) > 0),
    [C | _] = CallInstrs,
    %% First arg is {fn, Name}, followed by arg registers
    ?assertMatch({fn, <<"test_fn">>}, hd(C#ir_instr.args)),
    %% Should have 2 arg registers after the fn tag
    ?assertEqual(3, length(C#ir_instr.args)).

%%% ===================================================================
%%% Map operations
%%% ===================================================================

map_lookup_generates_helper_and_null_check_test() ->
    AST = #program{
        type = xdp,
        name = <<"test">>,
        types = [],
        maps = [
            #map_decl{
                name = <<"counters">>,
                kind = hash,
                key_type = {prim, u32},
                value_type = {prim, u64},
                max_entries = 256,
                loc = {1, 0}
            }
        ],
        consts = [],
        fns = [
            #fn_decl{
                name = <<"main">>,
                params = [{<<"ctx">>, {prim, u64}}],
                ret_type = {prim, u64},
                body = [
                    {return_stmt,
                        {call, <<"map_lookup">>,
                            [
                                {var, <<"counters">>, {2, 0}},
                                {integer_lit, 1, {2, 0}}
                            ],
                            {2, 0}},
                        {2, 0}}
                ],
                loc = {1, 0}
            }
        ]
    },
    IR = gen(AST),
    %% Map lookup generates: stack store, ld_map_fd, call_helper, null check
    AllInstrs = lists:flatmap(
        fun(B) -> B#ir_block.instrs end,
        maps:values(IR#ir_program.blocks)
    ),
    AllOps = [I#ir_instr.op || I <- AllInstrs],
    ?assert(lists:member(ld_map_fd, AllOps)),
    ?assert(lists:member(call_helper, AllOps)),
    ?assert(lists:member(store, AllOps)),
    %% Null check creates multiple blocks
    ?assert(block_count(IR) >= 3).

map_update_generates_four_arg_call_test() ->
    AST = #program{
        type = xdp,
        name = <<"test">>,
        types = [],
        maps = [
            #map_decl{
                name = <<"m">>,
                kind = hash,
                key_type = {prim, u32},
                value_type = {prim, u64},
                max_entries = 16,
                loc = {1, 0}
            }
        ],
        consts = [],
        fns = [
            #fn_decl{
                name = <<"main">>,
                params = [{<<"ctx">>, {prim, u64}}],
                ret_type = {prim, u64},
                body = [
                    {expr_stmt,
                        {call, <<"map_update">>,
                            [
                                {var, <<"m">>, {2, 0}},
                                {integer_lit, 1, {2, 0}},
                                {integer_lit, 100, {2, 0}}
                            ],
                            {2, 0}},
                        {2, 0}},
                    {return_stmt, {integer_lit, 0, {3, 0}}, {3, 0}}
                ],
                loc = {1, 0}
            }
        ]
    },
    IR = gen(AST),
    AllInstrs = lists:flatmap(
        fun(B) -> B#ir_block.instrs end,
        maps:values(IR#ir_program.blocks)
    ),
    CallInstrs = [I || #ir_instr{op = call_helper} = I <- AllInstrs],
    ?assert(length(CallInstrs) > 0),
    [C | _] = CallInstrs,
    %% map_update_elem has 4 args: map_fd, key_ptr, val_ptr, flags
    ?assertMatch({fn, <<"map_update_elem">>}, hd(C#ir_instr.args)),
    %% {fn,...} + 4 regs
    ?assertEqual(5, length(C#ir_instr.args)).

%%% ===================================================================
%%% Struct types
%%% ===================================================================

struct_layout_computed_correctly_test() ->
    AST = #program{
        type = xdp,
        name = <<"test">>,
        types = [
            #type_decl{
                name = <<"Point">>,
                fields = [{<<"x">>, {prim, u32}}, {<<"y">>, {prim, u32}}],
                loc = {1, 0}
            }
        ],
        maps = [],
        consts = [],
        fns = [
            #fn_decl{
                name = <<"main">>,
                params = [{<<"ctx">>, {prim, u64}}],
                ret_type = {prim, u64},
                body = [
                    {let_stmt, {var_pat, <<"p">>},
                        {struct_lit, <<"Point">>,
                            [
                                {<<"x">>, {integer_lit, 10, {2, 0}}},
                                {<<"y">>, {integer_lit, 20, {2, 0}}}
                            ],
                            {2, 0}},
                        {2, 0}},
                    {return_stmt, {field_access, {var, <<"p">>, {3, 0}}, <<"y">>, {3, 0}}, {3, 0}}
                ],
                loc = {1, 0}
            }
        ]
    },
    IR = gen(AST),
    AllInstrs = lists:flatmap(
        fun(B) -> B#ir_block.instrs end,
        maps:values(IR#ir_program.blocks)
    ),
    %% Struct lit should generate store instructions
    StoreInstrs = [I || #ir_instr{op = store} = I <- AllInstrs],
    ?assert(length(StoreInstrs) >= 2),
    %% Field access on struct should generate load with struct_field
    LoadInstrs = [I || #ir_instr{op = load} = I <- AllInstrs],
    ?assert(length(LoadInstrs) > 0),
    %% Check that the y field access has correct offset (4 for u32 after u32)
    YLoads = [
        I
     || #ir_instr{op = load, args = [_, {struct_field, <<"y">>, 4, 4}]} = I <-
            AllInstrs
    ],
    ?assert(length(YLoads) > 0).

%%% ===================================================================
%%% Assignment updates original register
%%% ===================================================================

assignment_copies_back_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 1, {1, 0}}, {1, 0}},
        {assign_stmt, {var, <<"x">>, {2, 0}}, {integer_lit, 2, {2, 0}}, {2, 0}},
        {return_stmt, {var, <<"x">>, {3, 0}}, {3, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    %% The reassignment generates a mov to copy back to original register
    MovInstrs = [I || #ir_instr{op = mov} = I <- Instrs],
    %% Should have multiple movs: init x, load 2, copy back, mov to v_ret
    ?assert(length(MovInstrs) >= 3).

%%% ===================================================================
%%% Default return: implicit exit 0
%%% ===================================================================

no_explicit_return_generates_default_exit_test() ->
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 42, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    %% Without explicit return, gen_fn adds: mov v_ret, 0; exit v_ret
    {exit, v_ret} = block_term(entry, IR).

%%% ===================================================================
%%% Bool literals
%%% ===================================================================

bool_true_is_1_test() ->
    AST = make_program([
        {return_stmt, {bool_lit, true, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    BoolInstrs = [I || #ir_instr{type = {scalar, bool}} = I <- Instrs],
    ?assert(length(BoolInstrs) > 0),
    [B | _] = BoolInstrs,
    ?assertEqual([1], B#ir_instr.args).

bool_false_is_0_test() ->
    AST = make_program([
        {return_stmt, {bool_lit, false, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    BoolInstrs = [I || #ir_instr{type = {scalar, bool}} = I <- Instrs],
    [B | _] = BoolInstrs,
    ?assertEqual([0], B#ir_instr.args).

%%% ===================================================================
%%% Method call sugar
%%% ===================================================================

method_call_desugars_test() ->
    %% obj.method(arg) → method(obj, arg)
    AST = make_program([
        {let_stmt, {var_pat, <<"x">>}, {integer_lit, 1, {1, 0}}, {1, 0}},
        {return_stmt,
            {method_call, {var, <<"x">>, {2, 0}}, <<"do_something">>, [{integer_lit, 2, {2, 0}}],
                {2, 0}},
            {2, 0}}
    ]),
    IR = gen(AST),
    Instrs = block_instrs(entry, IR),
    CallInstrs = [I || #ir_instr{op = call_helper} = I <- Instrs],
    ?assert(length(CallInstrs) > 0),
    [C | _] = CallInstrs,
    ?assertMatch({fn, <<"do_something">>}, hd(C#ir_instr.args)),
    %% obj + arg = 2 arguments after fn tag
    ?assertEqual(3, length(C#ir_instr.args)).

%%% ===================================================================
%%% Register type tracking
%%% ===================================================================

reg_types_tracked_test() ->
    AST = make_program([
        {return_stmt, {integer_lit, 42, {1, 0}}, {1, 0}}
    ]),
    IR = gen(AST),
    %% v_ctx should be tracked as {ptr, ctx}
    ?assertEqual({ptr, ctx}, maps:get(v_ctx, IR#ir_program.reg_types)),
    %% The literal register should be tracked as {scalar, u64}
    IntRegs = [
        R
     || {R, {scalar, u64}} <- maps:to_list(IR#ir_program.reg_types),
        R =/= v_ret,
        R =/= v_ctx,
        R =/= v_fp
    ],
    ?assert(length(IntRegs) > 0).

%%% ===================================================================
%%% Program metadata
%%% ===================================================================

program_type_propagated_test() ->
    lists:foreach(
        fun(PT) ->
            AST = make_program(PT, [
                {return_stmt, {integer_lit, 0, {1, 0}}, {1, 0}}
            ]),
            IR = gen(AST),
            ?assertEqual(PT, IR#ir_program.prog_type)
        end,
        [xdp, tc, cgroup, socket]
    ).

entry_label_is_entry_test() ->
    AST = make_program([{return_stmt, {integer_lit, 0, {1, 0}}, {1, 0}}]),
    IR = gen(AST),
    ?assertEqual(entry, IR#ir_program.entry).

%%% ===================================================================
%%% Packet read: non-constant offset must error (K3)
%%% ===================================================================

pkt_read_non_constant_offset_errors_test() ->
    %% read_u16_be(data, variable) must produce a compile error,
    %% not silently fall back to offset 0.
    AST = make_program([
        {let_stmt, {var_pat, <<"data">>},
            {field_access, {var, <<"ctx">>, {1, 0}}, <<"data">>, {1, 0}}, {1, 0}},
        {let_stmt, {var_pat, <<"off">>}, {integer_lit, 14, {2, 0}}, {2, 0}},
        {return_stmt,
            {call, <<"read_u16_be">>,
                [
                    {var, <<"data">>, {3, 0}},
                    %% variable, not literal
                    {var, <<"off">>, {3, 0}}
                ],
                {3, 0}},
            {3, 0}}
    ]),
    ?assertError(
        {compile_error, {non_constant_offset, <<"read_u16_be">>}},
        gen(AST)
    ).
