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

-module(ebl_parser_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebl_ast.hrl").

%%% ===================================================================
%%% WP-002 Acceptance: minimal program parses
%%% ===================================================================

acceptance_test() ->
    Src = <<
        "xdp my_prog do\n"
        "  fn main(ctx) -> action do\n"
        "    return :pass\n"
        "  end\n"
        "end"
    >>,
    {ok, Tokens} = ebl_lexer:tokenize(Src),
    {ok, Prog} = ebl_parser:parse(Tokens),
    ?assertEqual(xdp, Prog#program.type),
    ?assertEqual(<<"my_prog">>, Prog#program.name),
    ?assertEqual(1, length(Prog#program.fns)),
    [Fn] = Prog#program.fns,
    ?assertEqual(<<"main">>, Fn#fn_decl.name),
    ?assertEqual({prim, action}, Fn#fn_decl.ret_type).

%%% ===================================================================
%%% Program types
%%% ===================================================================

tc_program_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"tc my_filter do\nend">>),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual(tc, P#program.type).

program_with_direction_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"tc my_filter, :ingress do\nend">>),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual(ingress, P#program.direction).

%%% ===================================================================
%%% Type declarations
%%% ===================================================================

type_decl_test() ->
    Src = <<
        "xdp test do\n"
        "  type IpAddr do\n"
        "    addr : u32\n"
        "    port : u16\n"
        "  end\n"
        "end"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual(1, length(P#program.types)),
    [TD] = P#program.types,
    ?assertEqual(<<"IpAddr">>, TD#type_decl.name),
    ?assertEqual(2, length(TD#type_decl.fields)).

%%% ===================================================================
%%% Map declarations
%%% ===================================================================

map_decl_test() ->
    Src = <<
        "xdp test do\n"
        "  map :counters, hash, key: u32, value: u64, max_entries: 1024\n"
        "end"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual(1, length(P#program.maps)),
    [MD] = P#program.maps,
    ?assertEqual(<<"counters">>, MD#map_decl.name),
    ?assertEqual(hash, MD#map_decl.kind),
    ?assertEqual({prim, u32}, MD#map_decl.key_type),
    ?assertEqual({prim, u64}, MD#map_decl.value_type),
    ?assertEqual(1024, MD#map_decl.max_entries).

%%% ===================================================================
%%% Const declarations
%%% ===================================================================

const_decl_test() ->
    Src = <<
        "xdp test do\n"
        "  const MAX_SIZE : u32 = 1500\n"
        "end"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual(1, length(P#program.consts)),
    [CD] = P#program.consts,
    ?assertEqual(<<"MAX_SIZE">>, CD#const_decl.name).

%%% ===================================================================
%%% Function declarations
%%% ===================================================================

fn_no_ret_type_test() ->
    Src = <<
        "xdp test do\n"
        "  fn helper(x) do\n"
        "    return x\n"
        "  end\n"
        "end"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    ?assertEqual(undefined, Fn#fn_decl.ret_type).

fn_typed_params_test() ->
    Src = <<
        "xdp test do\n"
        "  fn add(a : u32, b : u32) -> u32 do\n"
        "    return a + b\n"
        "  end\n"
        "end"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    ?assertEqual(
        [{<<"a">>, {prim, u32}}, {<<"b">>, {prim, u32}}],
        Fn#fn_decl.params
    ),
    ?assertEqual({prim, u32}, Fn#fn_decl.ret_type).

%%% ===================================================================
%%% Statements
%%% ===================================================================

let_stmt_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    let y = 42\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{let_stmt, {var_pat, <<"y">>}, {integer_lit, 42, _}, _}] = Fn#fn_decl.body.

let_typed_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    let y : u32 = 42\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{let_stmt, {var_pat, <<"y">>}, {integer_lit, 42, _}, _}] = Fn#fn_decl.body.

assign_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    x = 10\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{assign_stmt, {var, <<"x">>, _}, {integer_lit, 10, _}, _}] = Fn#fn_decl.body.

return_atom_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(ctx) do\n    return :drop\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, {atom_lit, <<"drop">>, _}, _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% If/elif/else
%%% ===================================================================

if_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    if x == 1 do\n"
        "      return :drop\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{if_stmt, _, _, [], [], _}] = Fn#fn_decl.body.

if_else_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    if x == 1 do\n"
        "      return :drop\n"
        "    else\n"
        "      return :pass\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{if_stmt, _, [_], [], [_], _}] = Fn#fn_decl.body.

if_elif_else_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    if x == 1 do\n"
        "      return :drop\n"
        "    elif x == 2 do\n"
        "      return :pass\n"
        "    else\n"
        "      return :drop\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{if_stmt, _, [_], [{_, [_]}], [_], _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% For loop
%%% ===================================================================

for_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    for i in 0..10 do\n"
        "      x = x + 1\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{for_stmt, <<"i">>, _, _, [_], _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% Match
%%% ===================================================================

match_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    match x do\n"
        "      1 -> return :drop\n"
        "      _ -> return :pass\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{match_stmt, _, Arms, _}] = Fn#fn_decl.body,
    ?assertEqual(2, length(Arms)).

%%% ===================================================================
%%% Expressions — precedence
%%% ===================================================================

precedence_mul_add_test() ->
    %% 1 + 2 * 3 → should be (1 + (2 * 3))
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    return 1 + 2 * 3\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, Expr, _}] = Fn#fn_decl.body,
    ?assertMatch({binop, '+', {integer_lit, 1, _}, {binop, '*', _, _, _}, _}, Expr).

precedence_paren_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    return (1 + 2) * 3\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, Expr, _}] = Fn#fn_decl.body,
    ?assertMatch({binop, '*', {binop, '+', _, _, _}, {integer_lit, 3, _}, _}, Expr).

%%% ===================================================================
%%% Unary operators
%%% ===================================================================

unary_neg_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    return -x\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, {unop, '-', {var, <<"x">>, _}, _}, _}] = Fn#fn_decl.body.

unary_not_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    return !x\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, {unop, '!', _, _}, _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% Function calls
%%% ===================================================================

call_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(x) do\n    return foo(1, 2)\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, {call, <<"foo">>, [_, _], _}, _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% Field access
%%% ===================================================================

field_access_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp t do\n  fn f(ctx) do\n    return ctx.data\n  end\nend">>),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, {field_access, {var, <<"ctx">>, _}, <<"data">>, _}, _}] = Fn#fn_decl.body.

%%% ===================================================================
%%% Struct literal
%%% ===================================================================

struct_lit_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    let s = %MyStruct{a: 1, b: 2}\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{let_stmt, _, {struct_lit, <<"MyStruct">>, Fields, _}, _}] = Fn#fn_decl.body,
    ?assertEqual(2, length(Fields)).

%%% ===================================================================
%%% Some/None
%%% ===================================================================

some_none_test() ->
    Src = <<
        "xdp t do\n  fn f(x) do\n"
        "    match x do\n"
        "      Some(v) -> return v\n"
        "      None -> return 0\n"
        "    end\n"
        "  end\nend"
    >>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [
        {match_stmt, _,
            [
                {{some_pat, {var_pat, <<"v">>}}, _},
                {{none_pat}, _}
            ],
            _}
    ] = Fn#fn_decl.body.

%%% ===================================================================
%%% Error handling
%%% ===================================================================

parse_error_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"42">>),
    ?assertMatch({error, {_, {_, _}}}, ebl_parser:parse(T)).

%%% ===================================================================
%%% Empty program
%%% ===================================================================

empty_program_test() ->
    {ok, T} = ebl_lexer:tokenize(<<"xdp test do\nend">>),
    {ok, P} = ebl_parser:parse(T),
    ?assertEqual([], P#program.fns),
    ?assertEqual([], P#program.types),
    ?assertEqual([], P#program.maps).

%%% ===================================================================
%%% Boolean expressions
%%% ===================================================================

logical_and_or_test() ->
    Src = <<"xdp t do\n  fn f(a) do\n    return a && true || false\n  end\nend">>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, P} = ebl_parser:parse(T),
    [Fn] = P#program.fns,
    [{return_stmt, Expr, _}] = Fn#fn_decl.body,
    %% || has lower precedence than && → (a && true) || false
    ?assertMatch({binop, '||', {binop, '&&', _, _, _}, _, _}, Expr).
