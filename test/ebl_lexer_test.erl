-module(ebl_lexer_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% WP-001 Acceptance Criterion:
%%% ebl_lexer:tokenize(<<"let x : u32 = 42">>) = correct token list
%%% ===================================================================

acceptance_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"let x : u32 = 42">>),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([let_kw, ident, colon, u32_kw, eq, integer_lit, eof], Types).

%%% ===================================================================
%%% Keywords
%%% ===================================================================

keywords_test_() ->
    KWs = [
        {<<"do">>,       do_kw},
        {<<"end">>,      end_kw},
        {<<"fn">>,       fn_kw},
        {<<"let">>,      let_kw},
        {<<"if">>,       if_kw},
        {<<"elif">>,     elif_kw},
        {<<"else">>,     else_kw},
        {<<"for">>,      for_kw},
        {<<"in">>,       in_kw},
        {<<"match">>,    match_kw},
        {<<"return">>,   return_kw},
        {<<"type">>,     type_kw},
        {<<"map">>,      map_kw},
        {<<"const">>,    const_kw},
        {<<"true">>,     true_kw},
        {<<"false">>,    false_kw},
        {<<"sizeof">>,   sizeof_kw},
        {<<"break">>,    break_kw},
        {<<"continue">>, continue_kw},
        {<<"action">>,   action_kw},
        {<<"xdp">>,      xdp_kw},
        {<<"tc">>,       tc_kw},
        {<<"u8">>,       u8_kw},
        {<<"u16">>,      u16_kw},
        {<<"u32">>,      u32_kw},
        {<<"u64">>,      u64_kw},
        {<<"i8">>,       i8_kw},
        {<<"i16">>,      i16_kw},
        {<<"i32">>,      i32_kw},
        {<<"i64">>,      i64_kw},
        {<<"bool">>,     bool_kw}
    ],
    [{binary_to_list(Src), fun() ->
        {ok, [{token, Type, _, _, _} | _]} = ebl_lexer:tokenize(Src),
        ?assertEqual(Expected, Type)
    end} || {Src, Expected} <- KWs].

%%% ===================================================================
%%% Identifiers
%%% ===================================================================

ident_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"my_var">>),
    ?assertMatch({token, ident, <<"my_var">>, 1, 1}, T).

type_ident_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"MyStruct">>),
    ?assertMatch({token, type_ident, <<"MyStruct">>, 1, 1}, T).

some_none_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"Some None">>),
    Types = [Ty || {token, Ty, _, _, _} <- Tokens],
    ?assertEqual([some_kw, none_kw, eof], Types).

underscore_ident_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"_unused">>),
    ?assertMatch({token, ident, <<"_unused">>, _, _}, T).

%%% ===================================================================
%%% Number literals
%%% ===================================================================

decimal_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"42">>),
    ?assertMatch({token, integer_lit, 42, _, _}, T).

hex_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"0xFF">>),
    ?assertMatch({token, integer_lit, 255, _, _}, T).

binary_lit_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"0b1010">>),
    ?assertMatch({token, integer_lit, 10, _, _}, T).

octal_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"0o77">>),
    ?assertMatch({token, integer_lit, 63, _, _}, T).

underscore_separator_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"1_000_000">>),
    ?assertMatch({token, integer_lit, 1000000, _, _}, T).

hex_underscore_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"0xDEAD_BEEF">>),
    ?assertMatch({token, integer_lit, 16#DEADBEEF, _, _}, T).

%%% ===================================================================
%%% Atom literals
%%% ===================================================================

atom_lit_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<":drop">>),
    ?assertMatch({token, atom_lit, <<"drop">>, 1, 1}, T).

atom_pass_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<":pass">>),
    ?assertMatch({token, atom_lit, <<"pass">>, _, _}, T).

%%% ===================================================================
%%% Operators
%%% ===================================================================

two_char_ops_test_() ->
    Ops = [
        {<<"|>">>, pipe},
        {<<"||">>, or_or},
        {<<"&&">>, and_and},
        {<<"==">>, eq_eq},
        {<<"!=">>, bang_eq},
        {<<"<=">>, lt_eq},
        {<<">=">>, gt_eq},
        {<<"<<">>, lshift},
        {<<">>">>, rshift},
        {<<"->">>, arrow},
        {<<"..">>, dotdot},
        {<<"?.">>, question_dot}
    ],
    [{binary_to_list(Src), fun() ->
        {ok, [T | _]} = ebl_lexer:tokenize(Src),
        ?assertMatch({token, Expected, _, _, _}, T)
    end} || {Src, Expected} <- Ops].

three_char_op_test() ->
    {ok, [T | _]} = ebl_lexer:tokenize(<<"..=">>),
    ?assertMatch({token, dotdoteq, _, _, _}, T).

single_char_ops_test_() ->
    Ops = [
        {<<"|">>,  pipe_op},
        {<<"^">>,  caret},
        {<<"&">>,  ampersand},
        {<<"<">>,  lt},
        {<<">">>,  gt},
        {<<"+">>,  plus},
        {<<"-">>,  minus},
        {<<"*">>,  star},
        {<<"/">>,  slash},
        {<<"%">>,  percent},
        {<<"!">>,  bang},
        {<<"~">>,  tilde},
        {<<"(">>,  lparen},
        {<<")">>,  rparen},
        {<<"{">>,  lbrace},
        {<<"}">>,  rbrace},
        {<<"[">>,  lbracket},
        {<<"]">>,  rbracket},
        {<<",">>,  comma},
        {<<":">>,  colon},
        {<<";">>,  semicolon},
        {<<".">>,  dot},
        {<<"=">>,  eq}
    ],
    [{binary_to_list(Src), fun() ->
        {ok, [T | _]} = ebl_lexer:tokenize(Src),
        ?assertMatch({token, Expected, _, _, _}, T)
    end} || {Src, Expected} <- Ops].

%%% ===================================================================
%%% Newlines
%%% ===================================================================

newline_significant_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"a\nb">>),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([ident, newline, ident, eof], Types).

newline_collapse_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"a\n\n\nb">>),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([ident, newline, ident, eof], Types).

%%% ===================================================================
%%% Comments
%%% ===================================================================

comment_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"x # comment\ny">>),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([ident, newline, ident, eof], Types).

%%% ===================================================================
%%% Boolean literals
%%% ===================================================================

bool_values_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"true false">>),
    Vals = [{Ty, V} || {token, Ty, V, _, _} <- Tokens, Ty =/= eof],
    ?assertEqual([{true_kw, true}, {false_kw, false}], Vals).

%%% ===================================================================
%%% Source location tracking
%%% ===================================================================

location_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"  let x">>),
    [{token, let_kw, _, 1, 3}, {token, ident, <<"x">>, 1, 7} | _] = Tokens.

%%% ===================================================================
%%% Error handling
%%% ===================================================================

unexpected_char_test() ->
    ?assertMatch({error, {{unexpected_char, $`}, _, _}},
                 ebl_lexer:tokenize(<<"`">>)).

%%% ===================================================================
%%% Full program snippet
%%% ===================================================================

mini_program_test() ->
    Src = <<"fn main(ctx) -> action do\n"
            "  return :pass\n"
            "end">>,
    {ok, Tokens} = ebl_lexer:tokenize(Src),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([fn_kw, ident, lparen, ident, rparen, arrow, action_kw,
                  do_kw, newline, return_kw, atom_lit, newline, end_kw, eof],
                 Types).

%%% ===================================================================
%%% Map type keywords
%%% ===================================================================

map_types_test_() ->
    KWs = [
        {<<"hash">>,          hash_kw},
        {<<"array">>,         array_kw},
        {<<"lru_hash">>,      lru_hash_kw},
        {<<"percpu_hash">>,   percpu_hash_kw},
        {<<"percpu_array">>,  percpu_array_kw},
        {<<"ringbuf">>,       ringbuf_kw}
    ],
    [{binary_to_list(Src), fun() ->
        {ok, [{token, Type, _, _, _} | _]} = ebl_lexer:tokenize(Src),
        ?assertEqual(Expected, Type)
    end} || {Src, Expected} <- KWs].

%%% ===================================================================
%%% Empty input
%%% ===================================================================

empty_input_test() ->
    {ok, [T]} = ebl_lexer:tokenize(<<>>),
    ?assertMatch({token, eof, _, _, _}, T).

%%% ===================================================================
%%% Pipe operator in expression
%%% ===================================================================

pipe_expression_test() ->
    {ok, Tokens} = ebl_lexer:tokenize(<<"x |> foo">>),
    Types = [T || {token, T, _, _, _} <- Tokens],
    ?assertEqual([ident, pipe, ident, eof], Types).

%%% ===================================================================
%%% Multiple newlines must advance line counter (K5)
%%% ===================================================================

multiple_newlines_line_count_test() ->
    %% "a\n\n\nb" — token b must be on line 4, not line 2
    {ok, Tokens} = ebl_lexer:tokenize(<<"a\n\n\nb">>),
    %% Find the token for "b"
    BToken = [T || {token, ident, <<"b">>, _, _} = T <- Tokens],
    ?assertMatch([{token, ident, <<"b">>, 4, 1}], BToken).

multiple_newlines_with_cr_test() ->
    %% "a\r\n\r\nb" — token b must be on line 3
    {ok, Tokens} = ebl_lexer:tokenize(<<"a\r\n\r\nb">>),
    BToken = [T || {token, ident, <<"b">>, _, _} = T <- Tokens],
    ?assertMatch([{token, ident, <<"b">>, 3, 1}], BToken).
