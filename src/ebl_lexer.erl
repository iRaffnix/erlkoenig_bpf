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

-module(ebl_lexer).
-moduledoc """
EBL (Erlkoenig BPF Language) lexer.

Tokenizes EBL source code (binary) into a list of token records.
Implements the lexical grammar from TR-07 / SYNTAX_REFERENCE.

Features:
- Binary pattern matching for efficient single-pass tokenization
- Keyword table (atoms for all reserved words)
- Source location tracking (line, column)
- Number literals: decimal, hex (0x), binary (0b), octal (0o), with _ separators
- Atom literals (:ident)
- Line comments (#)
- Newlines as significant tokens (statement separators)
""".

-export([tokenize/1]).
-export_type([token/0, token_type/0]).

-record(token, {
    type :: token_type(),
    value :: term(),
    line :: pos_integer(),
    col :: non_neg_integer()
}).

-type token() :: #token{}.

-type token_type() ::
    %% Literals
    integer_lit
    | true_kw
    | false_kw
    | atom_lit
    %% Identifiers
    | ident
    | type_ident
    %% Keywords
    | do_kw
    | end_kw
    | fn_kw
    | let_kw
    | if_kw
    | elif_kw
    | else_kw
    | for_kw
    | in_kw
    | match_kw
    | return_kw
    | type_kw
    | map_kw
    | const_kw
    | some_kw
    | none_kw
    | sizeof_kw
    | break_kw
    | continue_kw
    %% Program types
    | xdp_kw
    | tc_kw
    | cgroup_kw
    | socket_kw
    %% Primitive types
    | u8_kw
    | u16_kw
    | u32_kw
    | u64_kw
    | i8_kw
    | i16_kw
    | i32_kw
    | i64_kw
    | bool_kw
    | action_kw
    %% Map types
    | hash_kw
    | array_kw
    | lru_hash_kw
    | percpu_hash_kw
    | percpu_array_kw
    | lru_percpu_hash_kw
    | ringbuf_kw
    | devmap_hash_kw
    | prog_array_kw
    %% Operators
    | pipe
    | pipe_op
    | or_or
    | and_and
    | caret
    | ampersand
    | eq_eq
    | bang_eq
    | lt
    | gt
    | lt_eq
    | gt_eq
    | lshift
    | rshift
    | plus
    | minus
    | star
    | slash
    | percent
    | bang
    | tilde
    %% Delimiters
    | lparen
    | rparen
    | lbrace
    | rbrace
    | lbracket
    | rbracket
    | comma
    | colon
    | semicolon
    | dot
    | dotdot
    | dotdoteq
    | arrow
    | eq
    | underscore
    %% Special
    | newline
    | eof.

-doc "Tokenize EBL source binary into a list of tokens.".
-spec tokenize(binary()) -> {ok, [token()]} | {error, {term(), pos_integer(), pos_integer()}}.
tokenize(Source) when is_binary(Source) ->
    try
        Tokens = scan(Source, 1, 1, []),
        {ok, Tokens}
    catch
        throw:{lex_error, Reason, Line, Col} ->
            {error, {Reason, Line, Col}}
    end.

%%% ===================================================================
%%% Scanner
%%% ===================================================================

scan(<<>>, Line, _Col, Acc) ->
    lists:reverse([#token{type = eof, value = eof, line = Line, col = 0} | Acc]);
%% Skip whitespace (not newlines)
scan(<<$\s, Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 1, Acc);
scan(<<$\t, Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 1, Acc);
scan(<<$\r, Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 1, Acc);
%% Newlines — significant as statement separators, collapse multiple
scan(<<$\n, Rest/binary>>, Line, _Col, Acc) ->
    {Rest2, ExtraLines} = skip_extra_newlines(Rest),
    NextLine = Line + 1 + ExtraLines,
    case Acc of
        [#token{type = newline} | _] ->
            %% Already have a newline token, skip duplicate
            scan(Rest2, NextLine, 1, Acc);
        _ ->
            scan(
                Rest2,
                NextLine,
                1,
                [#token{type = newline, value = nl, line = Line, col = 0} | Acc]
            )
    end;
%% Line comments (# to EOL)
scan(<<$#, Rest/binary>>, Line, Col, Acc) ->
    Rest2 = skip_to_eol(Rest),
    scan(Rest2, Line, Col, Acc);
%% Three-character operators
scan(<<"..=", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 3, [tok(dotdoteq, '..=', Line, Col) | Acc]);
%% Two-character operators (check before single-char)
scan(<<"|>", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(pipe, '|>', Line, Col) | Acc]);
scan(<<"||", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(or_or, '||', Line, Col) | Acc]);
scan(<<"&&", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(and_and, '&&', Line, Col) | Acc]);
scan(<<"==", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(eq_eq, '==', Line, Col) | Acc]);
scan(<<"!=", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(bang_eq, '!=', Line, Col) | Acc]);
scan(<<"<=", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(lt_eq, '<=', Line, Col) | Acc]);
scan(<<">=", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(gt_eq, '>=', Line, Col) | Acc]);
scan(<<"<<", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(lshift, '<<', Line, Col) | Acc]);
scan(<<">>", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(rshift, '>>', Line, Col) | Acc]);
scan(<<"->", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(arrow, '->', Line, Col) | Acc]);
scan(<<"..", Rest/binary>>, Line, Col, Acc) ->
    scan(Rest, Line, Col + 2, [tok(dotdot, '..', Line, Col) | Acc]);
%% Option chaining ?. is not supported — give a clear error
scan(<<"?.", _/binary>>, Line, Col, _Acc) ->
    throw({lex_error, {unsupported_feature, option_chaining}, Line, Col});
%% Atom literals (:ident) — must come before single colon
scan(<<$:, C, Rest/binary>>, Line, Col, Acc) when
    (C >= $a andalso C =< $z); C =:= $_
->
    {Name, Rest2, Len} = scan_ident_chars(<<C, Rest/binary>>, <<>>),
    scan(
        Rest2,
        Line,
        Col + 1 + Len,
        [#token{type = atom_lit, value = Name, line = Line, col = Col} | Acc]
    );
%% Single-character operators and delimiters
scan(<<$|, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(pipe_op, '|', L, C) | Acc]);
scan(<<$^, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(caret, '^', L, C) | Acc]);
scan(<<$&, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(ampersand, '&', L, C) | Acc]);
scan(<<$<, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(lt, '<', L, C) | Acc]);
scan(<<$>, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(gt, '>', L, C) | Acc]);
scan(<<$+, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(plus, '+', L, C) | Acc]);
scan(<<$-, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(minus, '-', L, C) | Acc]);
scan(<<$*, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(star, '*', L, C) | Acc]);
scan(<<$/, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(slash, '/', L, C) | Acc]);
scan(<<$%, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(percent, '%', L, C) | Acc]);
scan(<<$!, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(bang, '!', L, C) | Acc]);
scan(<<$~, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(tilde, '~', L, C) | Acc]);
scan(<<$(, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(lparen, '(', L, C) | Acc]);
scan(<<$), Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(rparen, ')', L, C) | Acc]);
scan(<<${, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(lbrace, '{', L, C) | Acc]);
scan(<<$}, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(rbrace, '}', L, C) | Acc]);
scan(<<$[, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(lbracket, '[', L, C) | Acc]);
scan(<<$], Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(rbracket, ']', L, C) | Acc]);
scan(<<$,, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(comma, ',', L, C) | Acc]);
scan(<<$:, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(colon, ':', L, C) | Acc]);
scan(<<$;, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(semicolon, ';', L, C) | Acc]);
scan(<<$., Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(dot, '.', L, C) | Acc]);
scan(<<$=, Rest/binary>>, L, C, Acc) ->
    scan(Rest, L, C + 1, [tok(eq, '=', L, C) | Acc]);
%% Number literals
scan(<<"0x", Rest/binary>>, Line, Col, Acc) ->
    {Val, Rest2, Len} = scan_hex(Rest, 0, 0),
    scan(
        Rest2,
        Line,
        Col + 2 + Len,
        [#token{type = integer_lit, value = Val, line = Line, col = Col} | Acc]
    );
scan(<<"0b", Rest/binary>>, Line, Col, Acc) ->
    {Val, Rest2, Len} = scan_bin(Rest, 0, 0),
    scan(
        Rest2,
        Line,
        Col + 2 + Len,
        [#token{type = integer_lit, value = Val, line = Line, col = Col} | Acc]
    );
scan(<<"0o", Rest/binary>>, Line, Col, Acc) ->
    {Val, Rest2, Len} = scan_oct(Rest, 0, 0),
    scan(
        Rest2,
        Line,
        Col + 2 + Len,
        [#token{type = integer_lit, value = Val, line = Line, col = Col} | Acc]
    );
scan(<<C, _/binary>> = Bin, Line, Col, Acc) when C >= $0, C =< $9 ->
    {Val, Rest2, Len} = scan_dec(Bin, 0, 0),
    scan(
        Rest2,
        Line,
        Col + Len,
        [#token{type = integer_lit, value = Val, line = Line, col = Col} | Acc]
    );
%% Identifiers and keywords (lowercase or underscore start)
scan(<<C, _/binary>> = Bin, Line, Col, Acc) when (C >= $a andalso C =< $z); C =:= $_ ->
    {Name, Rest, Len} = scan_ident_chars(Bin, <<>>),
    Type = keyword_or_ident(Name),
    Value =
        case Type of
            ident -> Name;
            true_kw -> true;
            false_kw -> false;
            _ -> Name
        end,
    scan(
        Rest,
        Line,
        Col + Len,
        [#token{type = Type, value = Value, line = Line, col = Col} | Acc]
    );
%% Type identifiers (uppercase start)
scan(<<C, _/binary>> = Bin, Line, Col, Acc) when C >= $A, C =< $Z ->
    {Name, Rest, Len} = scan_ident_chars(Bin, <<>>),
    Type =
        case Name of
            <<"Some">> -> some_kw;
            <<"None">> -> none_kw;
            _ -> type_ident
        end,
    scan(
        Rest,
        Line,
        Col + Len,
        [#token{type = Type, value = Name, line = Line, col = Col} | Acc]
    );
%% Unknown character
scan(<<C, _/binary>>, Line, Col, _Acc) ->
    throw({lex_error, {unexpected_char, C}, Line, Col}).

%%% ===================================================================
%%% Number scanners
%%% ===================================================================

scan_dec(<<C, Rest/binary>>, Val, Len) when C >= $0, C =< $9 ->
    scan_dec(Rest, Val * 10 + (C - $0), Len + 1);
scan_dec(<<$_, C, Rest/binary>>, Val, Len) when C >= $0, C =< $9 ->
    scan_dec(Rest, Val * 10 + (C - $0), Len + 2);
scan_dec(Rest, Val, Len) ->
    {Val, Rest, Len}.

scan_hex(<<C, Rest/binary>>, Val, Len) when C >= $0, C =< $9 ->
    scan_hex(Rest, Val * 16 + (C - $0), Len + 1);
scan_hex(<<C, Rest/binary>>, Val, Len) when C >= $a, C =< $f ->
    scan_hex(Rest, Val * 16 + (C - $a + 10), Len + 1);
scan_hex(<<C, Rest/binary>>, Val, Len) when C >= $A, C =< $F ->
    scan_hex(Rest, Val * 16 + (C - $A + 10), Len + 1);
scan_hex(<<$_, C, Rest/binary>>, Val, Len) when
    (C >= $0 andalso C =< $9);
    (C >= $a andalso C =< $f);
    (C >= $A andalso C =< $F)
->
    scan_hex(<<C, Rest/binary>>, Val, Len + 1);
scan_hex(Rest, Val, Len) ->
    {Val, Rest, Len}.

scan_bin(<<$0, Rest/binary>>, Val, Len) ->
    scan_bin(Rest, Val * 2, Len + 1);
scan_bin(<<$1, Rest/binary>>, Val, Len) ->
    scan_bin(Rest, Val * 2 + 1, Len + 1);
scan_bin(<<$_, C, Rest/binary>>, Val, Len) when C =:= $0; C =:= $1 ->
    scan_bin(<<C, Rest/binary>>, Val, Len + 1);
scan_bin(Rest, Val, Len) ->
    {Val, Rest, Len}.

scan_oct(<<C, Rest/binary>>, Val, Len) when C >= $0, C =< $7 ->
    scan_oct(Rest, Val * 8 + (C - $0), Len + 1);
scan_oct(<<$_, C, Rest/binary>>, Val, Len) when C >= $0, C =< $7 ->
    scan_oct(<<C, Rest/binary>>, Val, Len + 1);
scan_oct(Rest, Val, Len) ->
    {Val, Rest, Len}.

%%% ===================================================================
%%% Identifier scanner
%%% ===================================================================

scan_ident_chars(<<C, Rest/binary>>, Acc) when
    (C >= $a andalso C =< $z);
    (C >= $A andalso C =< $Z);
    (C >= $0 andalso C =< $9);
    C =:= $_
->
    scan_ident_chars(Rest, <<Acc/binary, C>>);
scan_ident_chars(Rest, Acc) ->
    {Acc, Rest, byte_size(Acc)}.

%%% ===================================================================
%%% Keyword table
%%% ===================================================================

keyword_or_ident(<<"do">>) -> do_kw;
keyword_or_ident(<<"end">>) -> end_kw;
keyword_or_ident(<<"fn">>) -> fn_kw;
keyword_or_ident(<<"let">>) -> let_kw;
keyword_or_ident(<<"if">>) -> if_kw;
keyword_or_ident(<<"elif">>) -> elif_kw;
keyword_or_ident(<<"else">>) -> else_kw;
keyword_or_ident(<<"for">>) -> for_kw;
keyword_or_ident(<<"in">>) -> in_kw;
keyword_or_ident(<<"match">>) -> match_kw;
keyword_or_ident(<<"return">>) -> return_kw;
keyword_or_ident(<<"type">>) -> type_kw;
keyword_or_ident(<<"map">>) -> map_kw;
keyword_or_ident(<<"const">>) -> const_kw;
keyword_or_ident(<<"true">>) -> true_kw;
keyword_or_ident(<<"false">>) -> false_kw;
keyword_or_ident(<<"sizeof">>) -> sizeof_kw;
keyword_or_ident(<<"break">>) -> break_kw;
keyword_or_ident(<<"continue">>) -> continue_kw;
keyword_or_ident(<<"action">>) -> action_kw;
%% Program types
keyword_or_ident(<<"xdp">>) -> xdp_kw;
keyword_or_ident(<<"tc">>) -> tc_kw;
keyword_or_ident(<<"cgroup">>) -> cgroup_kw;
keyword_or_ident(<<"socket">>) -> socket_kw;
%% Primitive types
keyword_or_ident(<<"u8">>) -> u8_kw;
keyword_or_ident(<<"u16">>) -> u16_kw;
keyword_or_ident(<<"u32">>) -> u32_kw;
keyword_or_ident(<<"u64">>) -> u64_kw;
keyword_or_ident(<<"i8">>) -> i8_kw;
keyword_or_ident(<<"i16">>) -> i16_kw;
keyword_or_ident(<<"i32">>) -> i32_kw;
keyword_or_ident(<<"i64">>) -> i64_kw;
keyword_or_ident(<<"bool">>) -> bool_kw;
%% Map types
keyword_or_ident(<<"hash">>) -> hash_kw;
keyword_or_ident(<<"array">>) -> array_kw;
keyword_or_ident(<<"lru_hash">>) -> lru_hash_kw;
keyword_or_ident(<<"percpu_hash">>) -> percpu_hash_kw;
keyword_or_ident(<<"percpu_array">>) -> percpu_array_kw;
keyword_or_ident(<<"lru_percpu_hash">>) -> lru_percpu_hash_kw;
keyword_or_ident(<<"ringbuf">>) -> ringbuf_kw;
keyword_or_ident(<<"devmap_hash">>) -> devmap_hash_kw;
keyword_or_ident(<<"prog_array">>) -> prog_array_kw;
%% Not a keyword
keyword_or_ident(_) -> ident.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

tok(Type, Value, Line, Col) ->
    #token{type = Type, value = Value, line = Line, col = Col}.

skip_to_eol(<<$\n, _/binary>> = Rest) -> Rest;
skip_to_eol(<<>>) -> <<>>;
skip_to_eol(<<_, Rest/binary>>) -> skip_to_eol(Rest).

skip_extra_newlines(Bin) -> skip_extra_newlines(Bin, 0).

skip_extra_newlines(<<$\n, Rest/binary>>, N) -> skip_extra_newlines(Rest, N + 1);
skip_extra_newlines(<<$\r, Rest/binary>>, N) -> skip_extra_newlines(Rest, N);
skip_extra_newlines(Rest, N) -> {Rest, N}.
