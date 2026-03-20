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

-module(ebl_error_format).
-moduledoc """
Human-readable error formatting for EBL compiler errors.

Converts structured error tuples from lexer, parser, and typechecker
into formatted strings and JSON-friendly maps.
""".

-export([format/1, format_json/1]).

%%% ===================================================================
%%% Text formatting
%%% ===================================================================

-spec format(term()) -> iolist().
%% Lexer errors
format({{unexpected_char, C}, L, Col}) ->
    io_lib:format("Line ~B, Col ~B: unexpected character '~c'", [L, Col, C]);
format({unexpected_char, C, L, Col}) ->
    io_lib:format("Line ~B, Col ~B: unexpected character '~c'", [L, Col, C]);
format({unterminated_string, L, Col}) ->
    io_lib:format("Line ~B, Col ~B: unterminated string literal", [L, Col]);
%% Parser errors (with location from A1 fix)
format({{expected, Exp, got, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected ~s, got ~s",
        [L, C, token_name(Exp), token_name(Got)]
    );
format({{expected_ident, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected identifier, got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_type_ident, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected type name, got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_type, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected type expression, got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_integer, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected integer, got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_atom, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected atom literal, got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_prog_type, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected program type (xdp), got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_map_kind, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected map kind (hash, array, ...), got ~s",
        [L, C, token_name(Got)]
    );
format({{expected_ident, Expected, got, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected '~s', got ~s",
        [L, C, Expected, token_name(Got)]
    );
format({{unexpected_in_program, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: unexpected ~s in program body "
        "(expected fn, map, type, const, or end)",
        [L, C, token_name(Got)]
    );
format({{unexpected_token, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: unexpected ~s",
        [L, C, token_name(Got)]
    );
format({{unexpected_pattern, Got}, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: unexpected ~s in pattern",
        [L, C, token_name(Got)]
    );
format({expected_range_op, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected range operator (.. or ..=)",
        [L, C]
    );
format({expected_direction, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: expected direction (:ingress or :egress)",
        [L, C]
    );
%% Typecheck errors
format({type_error, Reason, {L, C}}) ->
    io_lib:format("Line ~B, Col ~B: type error: ~p", [L, C, Reason]);
format({undefined_var, Name, {L, C}}) ->
    io_lib:format("Line ~B, Col ~B: undefined variable '~s'", [L, C, Name]);
format({undefined_map, Name, {L, C}}) ->
    io_lib:format("Line ~B, Col ~B: undefined map '~s'", [L, C, Name]);
format({undefined_fn, Name, {L, C}}) ->
    io_lib:format("Line ~B, Col ~B: undefined function '~s'", [L, C, Name]);
format({unknown_field, TypeName, Field, {L, C}}) ->
    io_lib:format(
        "Line ~B, Col ~B: type '~s' has no field '~s'",
        [L, C, TypeName, Field]
    );
%% List of errors
format(Errs) when is_list(Errs) ->
    lists:join($\n, [format(E) || E <- Errs]);
%% Fallback
format(Other) ->
    io_lib:format("Error: ~p", [Other]).

%%% ===================================================================
%%% JSON formatting
%%% ===================================================================

-spec format_json(term()) ->
    #{message := binary(), line := integer(), col := integer(), phase := <<_:24, _:_*16>>}.
format_json(Err) ->
    #{
        message => iolist_to_binary(format(Err)),
        line => extract_line(Err),
        col => extract_col(Err),
        phase => detect_phase(Err)
    }.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

extract_line({_, {L, _}}) when is_integer(L) -> L;
extract_line({_, _, {L, _}}) when is_integer(L) -> L;
extract_line({_, _, _, {L, _}}) when is_integer(L) -> L;
extract_line({{_, _}, L, _}) when is_integer(L) -> L;
extract_line({_, _, L, _}) when is_integer(L) -> L;
extract_line(_) -> 0.

extract_col({_, {_, C}}) when is_integer(C) -> C;
extract_col({_, _, {_, C}}) when is_integer(C) -> C;
extract_col({_, _, _, {_, C}}) when is_integer(C) -> C;
extract_col({{_, _}, _, C}) when is_integer(C) -> C;
extract_col({_, _, _, C}) when is_integer(C) -> C;
extract_col(_) -> 0.

detect_phase({{unexpected_char, _}, _, _}) -> <<"lex">>;
detect_phase({unexpected_char, _, _, _}) -> <<"lex">>;
detect_phase({unterminated_string, _, _}) -> <<"lex">>;
detect_phase({_, {_, _}}) -> <<"parse">>;
detect_phase({type_error, _, _}) -> <<"typecheck">>;
detect_phase({undefined_var, _, _}) -> <<"typecheck">>;
detect_phase({undefined_map, _, _}) -> <<"typecheck">>;
detect_phase({undefined_fn, _, _}) -> <<"typecheck">>;
detect_phase({unknown_field, _, _, _}) -> <<"typecheck">>;
detect_phase(_) -> <<"unknown">>.

%% Map token types to human-readable names.
token_name(eof) ->
    <<"end of input">>;
token_name(newline) ->
    <<"newline">>;
token_name(lparen) ->
    <<"'('">>;
token_name(rparen) ->
    <<"')'">>;
token_name(lbrace) ->
    <<"'{'">>;
token_name(rbrace) ->
    <<"'}'">>;
token_name(lbracket) ->
    <<"'['">>;
token_name(rbracket) ->
    <<"']'">>;
token_name(comma) ->
    <<"','">>;
token_name(colon) ->
    <<"':'">>;
token_name(dot) ->
    <<"'.'">>;
token_name(eq) ->
    <<"'='">>;
token_name(arrow) ->
    <<"'->'">>;
token_name(do_kw) ->
    <<"'do'">>;
token_name(end_kw) ->
    <<"'end'">>;
token_name(fn_kw) ->
    <<"'fn'">>;
token_name(let_kw) ->
    <<"'let'">>;
token_name(if_kw) ->
    <<"'if'">>;
token_name(else_kw) ->
    <<"'else'">>;
token_name(elif_kw) ->
    <<"'elif'">>;
token_name(for_kw) ->
    <<"'for'">>;
token_name(in_kw) ->
    <<"'in'">>;
token_name(return_kw) ->
    <<"'return'">>;
token_name(match_kw) ->
    <<"'match'">>;
token_name(map_kw) ->
    <<"'map'">>;
token_name(type_kw) ->
    <<"'type'">>;
token_name(const_kw) ->
    <<"'const'">>;
token_name(xdp_kw) ->
    <<"'xdp'">>;
token_name(tc_kw) ->
    <<"'tc'">>;
token_name(cgroup_kw) ->
    <<"'cgroup'">>;
token_name(socket_kw) ->
    <<"'socket'">>;
token_name(ident) ->
    <<"identifier">>;
token_name(type_ident) ->
    <<"type name">>;
token_name(integer_lit) ->
    <<"integer">>;
token_name(atom_lit) ->
    <<"atom">>;
token_name(true_kw) ->
    <<"'true'">>;
token_name(false_kw) ->
    <<"'false'">>;
token_name(Other) when is_atom(Other) ->
    iolist_to_binary(io_lib:format("'~s'", [Other]));
token_name(Other) ->
    iolist_to_binary(io_lib:format("~p", [Other])).
