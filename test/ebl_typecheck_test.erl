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

-module(ebl_typecheck_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebl_ast.hrl").

%%% ===================================================================
%%% Unit tests for ebl_typecheck.erl
%%%
%%% Tests error paths, type compatibility, width promotion, boolean
%%% context, action validation, context fields, option types, and
%%% edge cases. Each test calls typecheck/1 which lexes+parses+checks.
%%% ===================================================================

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Parse and typecheck an EBL source string. Returns ok | {errors, List}.
typecheck(Src) when is_binary(Src) ->
    {ok, Tokens} = ebl_lexer:tokenize(Src),
    {ok, AST} = ebl_parser:parse(Tokens),
    case ebl_typecheck:check(AST) of
        {ok, _} -> ok;
        {error, Errs} -> {errors, Errs}
    end.

%% Wrap a body in a minimal XDP program returning action.
xdp(Body) ->
    iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        Body,
        <<"\n  end\n">>,
        <<"end">>
    ]).

%% (xdp_with/2 and xdp_u64_with/2 reserved for future use)

%% TC program type
tc(Body) ->
    iolist_to_binary([
        <<"tc test do\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        Body,
        <<"\n  end\n">>,
        <<"end">>
    ]).

%% Cgroup program type
cgroup(Body) ->
    iolist_to_binary([
        <<"cgroup test do\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        Body,
        <<"\n  end\n">>,
        <<"end">>
    ]).

%% XDP program returning u64
xdp_u64(Body) ->
    iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        Body,
        <<"\n  end\n">>,
        <<"end">>
    ]).

%% Assert typecheck succeeds
assert_ok(Src) ->
    ?assertEqual(ok, typecheck(Src)).

%% Assert typecheck fails with at least one error containing the given tag.
assert_has_error(Src, Tag) ->
    case typecheck(Src) of
        {errors, Errs} ->
            HasTag = lists:any(fun(E) -> element(1, E) =:= Tag end, Errs),
            ?assert(HasTag);
        ok ->
            ?assert(false, "Expected typecheck error but got ok")
    end.

%%% ===================================================================
%%% 1. Happy path — valid programs typecheck without errors
%%% ===================================================================

valid_return_action_test() ->
    assert_ok(xdp(<<"    return :pass">>)).

valid_let_integer_test() ->
    assert_ok(xdp(<<"    let x = 42\n    return :pass">>)).

valid_let_bool_test() ->
    assert_ok(xdp(<<"    let x = true\n    return :pass">>)).

valid_arithmetic_test() ->
    assert_ok(xdp_u64(<<"    let x = 1 + 2 * 3\n    return x">>)).

valid_comparison_test() ->
    assert_ok(
        xdp(<<"    let x = 1\n    if x == 0 do\n      return :drop\n    end\n    return :pass">>)
    ).

valid_logical_and_test() ->
    assert_ok(
        xdp(
            <<"    let x = 1\n    let y = 2\n    if x > 0 && y > 0 do\n      return :drop\n    end\n    return :pass">>
        )
    ).

valid_logical_or_test() ->
    assert_ok(
        xdp(
            <<"    let x = 1\n    if x == 0 || x == 1 do\n      return :drop\n    end\n    return :pass">>
        )
    ).

valid_negation_test() ->
    assert_ok(
        xdp(<<"    let x = true\n    if !x do\n      return :drop\n    end\n    return :pass">>)
    ).

valid_for_loop_test() ->
    assert_ok(
        xdp_u64(
            <<"    let sum = 0\n    for i in 0..10 do\n      sum = sum + i\n    end\n    return sum">>
        )
    ).

valid_if_elif_else_test() ->
    assert_ok(
        xdp(<<
            "    let x = 1\n"
            "    if x == 0 do\n"
            "      return :drop\n"
            "    elif x == 1 do\n"
            "      return :pass\n"
            "    else\n"
            "      return :drop\n"
            "    end\n"
            "    return :pass"
        >>)
    ).

valid_bitwise_ops_test() ->
    assert_ok(
        xdp_u64(
            <<"    let x = 0xFF & 0x0F\n    let y = x | 0xF0\n    let z = y ^ 0x55\n    return z">>
        )
    ).

valid_shift_ops_test() ->
    assert_ok(xdp_u64(<<"    let x = 1 << 4\n    let y = x >> 2\n    return y">>)).

valid_unary_minus_test() ->
    assert_ok(xdp_u64(<<"    let x = 5\n    let y = -x\n    return y">>)).

valid_bitwise_not_test() ->
    assert_ok(xdp_u64(<<"    let x = 42\n    let y = ~x\n    return y">>)).

valid_sizeof_test() ->
    assert_ok(xdp_u64(<<"    let s = sizeof(u32)\n    return s">>)).

%%% ===================================================================
%%% 2. Undefined variable
%%% ===================================================================

undefined_var_test() ->
    assert_has_error(
        xdp_u64(<<"    let y = unknown_var\n    return y">>),
        undefined_var
    ).

undefined_var_in_expr_test() ->
    assert_has_error(
        xdp_u64(<<"    return x + 1">>),
        undefined_var
    ).

%%% ===================================================================
%%% 3. Undefined function
%%% ===================================================================

undefined_fn_test() ->
    assert_has_error(
        xdp_u64(<<"    return nonexistent_fn(1, 2)">>),
        undefined_fn
    ).

%%% ===================================================================
%%% 4. Wrong argument count
%%% ===================================================================

wrong_arg_count_too_few_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn helper(a : u64, b : u64) -> u64 do\n">>,
        <<"    return a + b\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    return helper(1)\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, wrong_arg_count).

wrong_arg_count_too_many_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn helper(a : u64) -> u64 do\n">>,
        <<"    return a\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    return helper(1, 2, 3)\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, wrong_arg_count).

%%% ===================================================================
%%% 5. Type mismatch (assignment)
%%% ===================================================================

type_mismatch_struct_to_scalar_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type Point do\n">>,
        <<"    x : u32\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let p = %Point{x: 1, y: 2}\n">>,
        <<"    let x = 5\n">>,
        <<"    x = p\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, type_mismatch).

%%% ===================================================================
%%% 6. Undefined type (struct literal)
%%% ===================================================================

undefined_type_test() ->
    assert_has_error(
        xdp(<<"    let p = %NoSuchType{x: 1}\n    return :pass">>),
        undefined_type
    ).

%%% ===================================================================
%%% 7. Unknown struct field
%%% ===================================================================

unknown_field_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type Point do\n">>,
        <<"    x : u32\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let p = %Point{x: 1, y: 2}\n">>,
        <<"    let z = p.nonexistent\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, unknown_field).

%%% ===================================================================
%%% 8. Invalid action (wrong program type)
%%% ===================================================================

invalid_action_xdp_test() ->
    %% :ok is a TC action, not valid for XDP
    assert_has_error(
        xdp(<<"    return :ok">>),
        invalid_action
    ).

invalid_action_tc_test() ->
    %% :redirect is XDP-only
    assert_has_error(
        tc(<<"    return :redirect">>),
        invalid_action
    ).

invalid_action_bogus_test() ->
    assert_has_error(
        xdp(<<"    return :bogus_action">>),
        invalid_action
    ).

invalid_action_cgroup_test() ->
    %% :tx should fail for cgroup
    assert_has_error(
        cgroup(<<"    return :tx">>),
        invalid_action
    ).

%%% ===================================================================
%%% 9. Valid actions per program type
%%% ===================================================================

valid_xdp_actions_test() ->
    lists:foreach(
        fun(A) ->
            assert_ok(xdp(iolist_to_binary([<<"    return :">>, A])))
        end,
        [<<"drop">>, <<"pass">>, <<"tx">>, <<"redirect">>, <<"aborted">>]
    ).

valid_tc_actions_test() ->
    lists:foreach(
        fun(A) ->
            assert_ok(tc(iolist_to_binary([<<"    return :">>, A])))
        end,
        [<<"ok">>, <<"shot">>, <<"pipe">>, <<"drop">>, <<"pass">>]
    ).

valid_cgroup_actions_test() ->
    lists:foreach(
        fun(A) ->
            assert_ok(cgroup(iolist_to_binary([<<"    return :">>, A])))
        end,
        [<<"allow">>, <<"deny">>]
    ).

%%% ===================================================================
%%% 10. expect_bool — rejects non-scalar types in boolean context
%%% ===================================================================

expect_bool_struct_in_if_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type Point do\n">>,
        <<"    x : u32\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let p = %Point{x: 1, y: 2}\n">>,
        <<"    if p do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, expected_bool).

expect_bool_option_in_if_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :counter, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let key = 1\n">>,
        <<"    let result = counter.lookup(key)\n">>,
        <<"    if result do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, expected_bool).

expect_bool_action_in_if_test() ->
    Src = xdp(<<
        "    let a = :pass\n"
        "    if a do\n"
        "      return :drop\n"
        "    end\n"
        "    return :pass"
    >>),
    assert_has_error(Src, expected_bool).

%% Integer scalars should be allowed in boolean context (C-like truthiness)
expect_bool_integer_ok_test() ->
    assert_ok(
        xdp(<<"    let x = 42\n    if x do\n      return :drop\n    end\n    return :pass">>)
    ).

expect_bool_bool_ok_test() ->
    assert_ok(xdp(<<"    if true do\n      return :drop\n    end\n    return :pass">>)).

%%% ===================================================================
%%% 11. bool_in_arithmetic — reject bool + scalar arithmetic
%%% ===================================================================

bool_in_arithmetic_add_test() ->
    assert_has_error(
        xdp_u64(<<"    let x = true + 1">>),
        bool_in_arithmetic
    ).

bool_in_arithmetic_sub_test() ->
    assert_has_error(
        xdp_u64(<<"    let x = 5 - false">>),
        bool_in_arithmetic
    ).

bool_in_arithmetic_mul_test() ->
    assert_has_error(
        xdp_u64(<<"    let x = true * true">>),
        bool_in_arithmetic
    ).

%% Comparison with bool is OK (== / !=)
bool_comparison_ok_test() ->
    assert_ok(
        xdp(
            <<"    let x = true\n    if x == false do\n      return :drop\n    end\n    return :pass">>
        )
    ).

%% Logical ops with bool are OK
bool_logical_ok_test() ->
    assert_ok(xdp(<<"    if true && false do\n      return :drop\n    end\n    return :pass">>)).

%%% ===================================================================
%%% 12. wider_scalar symmetry (K4 fix verification)
%%% ===================================================================

wider_scalar_symmetry_test() ->
    %% u16 + i16 and i16 + u16 should both compile (mixed → unsigned)
    assert_ok(
        xdp_u64(<<"    let a : u16 = 1\n    let b : i16 = 2\n    let c = a + b\n    return c">>)
    ).

wider_scalar_symmetry_reverse_test() ->
    assert_ok(
        xdp_u64(<<"    let a : i16 = 1\n    let b : u16 = 2\n    let c = a + b\n    return c">>)
    ).

%%% ===================================================================
%%% 13. for loop bounds — non-integer
%%% ===================================================================

for_bounds_not_integer_bool_test() ->
    assert_has_error(
        xdp_u64(<<"    for i in true..10 do\n    end\n    return 0">>),
        for_bounds_not_integer
    ).

%%% ===================================================================
%%% 14. Context field validation
%%% ===================================================================

valid_ctx_field_xdp_test() ->
    assert_ok(xdp_u64(<<"    let d = ctx.data\n    return d">>)).

valid_ctx_field_data_end_test() ->
    assert_ok(xdp_u64(<<"    let d = ctx.data_end\n    return d">>)).

unknown_ctx_field_test() ->
    assert_has_error(
        xdp_u64(<<"    let d = ctx.nonexistent_field\n    return d">>),
        unknown_ctx_field
    ).

%%% ===================================================================
%%% 15. Map operations
%%% ===================================================================

valid_map_lookup_method_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :counter, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let key = 1\n">>,
        <<"    let result = counter.lookup(key)\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

valid_map_update_method_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :counter, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let key = 1\n">>,
        <<"    counter.update(key, 42)\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

valid_map_delete_method_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :counter, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let key = 1\n">>,
        <<"    counter.delete(key)\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 16. Built-in functions (packet reads)
%%% ===================================================================

valid_read_u8_test() ->
    assert_ok(xdp_u64(<<"    let v = read_u8(ctx, 0)\n    return v">>)).

valid_read_u16_test() ->
    assert_ok(xdp_u64(<<"    let v = read_u16(ctx, 0)\n    return v">>)).

valid_read_u32_test() ->
    assert_ok(xdp_u64(<<"    let v = read_u32(ctx, 0)\n    return v">>)).

valid_read_u16_be_test() ->
    assert_ok(xdp_u64(<<"    let v = read_u16_be(ctx, 0)\n    return v">>)).

valid_read_u32_be_test() ->
    assert_ok(xdp_u64(<<"    let v = read_u32_be(ctx, 0)\n    return v">>)).

%%% ===================================================================
%%% 17. Option types (Some / None)
%%% ===================================================================

valid_some_expr_test() ->
    assert_ok(xdp_u64(<<"    let x = Some(42)\n    return 0">>)).

valid_none_expr_test() ->
    assert_ok(xdp_u64(<<"    let x = None\n    return 0">>)).

valid_match_option_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :counter, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let key = 1\n">>,
        <<"    let result = counter.lookup(key)\n">>,
        <<"    match result do\n">>,
        <<"      Some(val) -> return :drop\n">>,
        <<"      None -> return :pass\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 18. Struct types
%%% ===================================================================

valid_struct_decl_and_use_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type Point do\n">>,
        <<"    x : u32\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let p = %Point{x: 10, y: 20}\n">>,
        <<"    let px = p.x\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

valid_struct_field_arithmetic_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type Point do\n">>,
        <<"    x : u32\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    let p = %Point{x: 10, y: 20}\n">>,
        <<"    let sum = p.x + p.y\n">>,
        <<"    return sum\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 20. Match statement
%%% ===================================================================

valid_match_literals_test() ->
    assert_ok(
        xdp(<<
            "    let x = 2\n"
            "    match x do\n"
            "      1 -> return :drop\n"
            "      2 -> return :pass\n"
            "      _ -> return :pass\n"
            "    end\n"
            "    return :pass"
        >>)
    ).

%%% ===================================================================
%%% 21. Multiple errors accumulate
%%% ===================================================================

multiple_errors_test() ->
    Src = xdp(<<
        "    let a = unknown1\n"
        "    let b = unknown2\n"
        "    return :bogus"
    >>),
    case typecheck(Src) of
        {errors, Errs} ->
            %% Should have at least 3 errors: 2 undefined_var + 1 invalid_action
            ?assert(length(Errs) >= 3);
        ok ->
            ?assert(false, "Expected errors")
    end.

%%% ===================================================================
%%% 22. Const declarations
%%% ===================================================================

valid_const_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  const THRESHOLD : u64 = 100\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let x = THRESHOLD\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 23. Break and continue
%%% ===================================================================

valid_break_continue_test() ->
    assert_ok(
        xdp_u64(<<
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      if i == 5 do\n"
            "        break\n"
            "      end\n"
            "      if i == 3 do\n"
            "        continue\n"
            "      end\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum"
        >>)
    ).

%%% ===================================================================
%%% 24. Multiple functions
%%% ===================================================================

valid_multi_fn_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn add(a : u64, b : u64) -> u64 do\n">>,
        <<"    return a + b\n">>,
        <<"  end\n">>,
        <<"  fn mul(a : u64, b : u64) -> u64 do\n">>,
        <<"    return a * b\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    let r = add(2, 3)\n">>,
        <<"    return mul(r, 4)\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 25. Logical operators with integer (C-like truthiness)
%%% ===================================================================

logical_and_with_integer_test() ->
    assert_ok(
        xdp(
            <<"    let x = 1\n    let y = 2\n    if x && y do\n      return :drop\n    end\n    return :pass">>
        )
    ).

logical_or_with_integer_test() ->
    assert_ok(
        xdp(<<"    let x = 0\n    if x || 1 do\n      return :drop\n    end\n    return :pass">>)
    ).

logical_not_with_integer_test() ->
    assert_ok(
        xdp(<<"    let x = 0\n    if !x do\n      return :drop\n    end\n    return :pass">>)
    ).

%%% ===================================================================
%%% 26. Logical operators reject non-scalar types
%%% ===================================================================

logical_and_struct_reject_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type S do\n">>,
        <<"    x : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let s = %S{x: 1}\n">>,
        <<"    if s && true do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, expected_bool).

%%% ===================================================================
%%% 27. Empty function body
%%% ===================================================================

empty_fn_body_test() ->
    assert_ok(xdp(<<"">>)).

%%% ===================================================================
%%% 28. Map as variable reference (no undefined_var error)
%%% ===================================================================

map_name_as_var_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  map :stats, hash, key: u32, value: u64, max_entries: 1024\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    let k = 1\n">>,
        <<"    let v = map_lookup(stats, k)\n">>,
        <<"    return v\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 29. Elif boolean context
%%% ===================================================================

elif_expects_bool_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type S do\n">>,
        <<"    x : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let x = 1\n">>,
        <<"    let s = %S{x: 1}\n">>,
        <<"    if x == 0 do\n">>,
        <<"      return :drop\n">>,
        <<"    elif s do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, expected_bool).

%%% ===================================================================
%%% 30. Comparison with incompatible types
%%% ===================================================================

comparison_struct_mismatch_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type A do\n">>,
        <<"    x : u32\n">>,
        <<"  end\n">>,
        <<"  type B do\n">>,
        <<"    y : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let a = %A{x: 1}\n">>,
        <<"    let b = %B{y: 2}\n">>,
        <<"    if a == b do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, type_mismatch).

%%% ===================================================================
%%% 31. Typed parameters
%%% ===================================================================

valid_typed_params_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  fn helper(a : u32, b : i32) -> u64 do\n">>,
        <<"    return a + b\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> u64 do\n">>,
        <<"    return helper(1, 2)\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_ok(Src).

%%% ===================================================================
%%% 32. for loop scoping — var not accessible after loop
%%% ===================================================================

for_var_scoped_test() ->
    assert_has_error(
        xdp_u64(<<"    for i in 0..10 do\n    end\n    return i">>),
        undefined_var
    ).

%%% ===================================================================
%%% 33. Action type compatible with scalar in assignment
%%% ===================================================================

action_scalar_compatible_test() ->
    %% action and scalar should be compatible (types_compatible returns true)
    assert_ok(
        xdp(<<
            "    let x = 1\n"
            "    x = :pass\n"
            "    return :pass"
        >>)
    ).

%%% ===================================================================
%%% 34. Negation rejects non-scalar
%%% ===================================================================

negation_struct_reject_test() ->
    Src = iolist_to_binary([
        <<"xdp test do\n">>,
        <<"  type S do\n">>,
        <<"    x : u32\n">>,
        <<"  end\n">>,
        <<"  fn main(ctx) -> action do\n">>,
        <<"    let s = %S{x: 1}\n">>,
        <<"    if !s do\n">>,
        <<"      return :drop\n">>,
        <<"    end\n">>,
        <<"    return :pass\n">>,
        <<"  end\n">>,
        <<"end">>
    ]),
    assert_has_error(Src, expected_bool).
