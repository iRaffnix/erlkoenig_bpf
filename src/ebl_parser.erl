%% @doc EBL recursive-descent parser with Pratt-style precedence climbing.
%%
%% Parses a token list from ebl_lexer into an AST defined in ebl_ast.hrl.
-module(ebl_parser).

-include("ebl_ast.hrl").

-export([parse/1]).

%% @doc Parse a complete EBL program from tokens.
-spec parse({ok, [tuple()]} | [tuple()]) -> {ok, #program{}} | {error, term()}.
parse({ok, Tokens}) ->
    parse(Tokens);
parse(Tokens) when is_list(Tokens) ->
    try
        {Prog, _Rest} = parse_program(Tokens),
        {ok, Prog}
    catch
        throw:{parse_error, Reason} ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Top-level: program
%%% ===================================================================

%% prog_type :name do ... end
parse_program(Tokens) ->
    T0 = skip_newlines(Tokens),
    {ProgType, T1} = expect_prog_type(T0),
    {Name, T2} = expect_ident(T1),
    T3 = skip_newlines(T2),
    {Dir, T4} = maybe_direction(T3),
    T5 = skip_newlines(T4),
    T6 = expect_token(do_kw, T5),
    T7 = skip_newlines(T6),
    {Decls, T8} = parse_decls(T7, [], [], [], []),
    T9 = skip_newlines(T8),
    T10 = expect_token(end_kw, T9),
    Prog = #program{type = ProgType, name = Name, direction = Dir,
                    types = lists:reverse(element(1, Decls)),
                    maps = lists:reverse(element(2, Decls)),
                    consts = lists:reverse(element(3, Decls)),
                    fns = lists:reverse(element(4, Decls))},
    {Prog, T10}.

parse_decls(Tokens, Types, Maps, Consts, Fns) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        end_kw ->
            {{Types, Maps, Consts, Fns}, T};
        eof ->
            {{Types, Maps, Consts, Fns}, T};
        type_kw ->
            {TD, T2} = parse_type_decl(T),
            parse_decls(T2, [TD | Types], Maps, Consts, Fns);
        map_kw ->
            {MD, T2} = parse_map_decl(T),
            parse_decls(T2, Types, [MD | Maps], Consts, Fns);
        const_kw ->
            {CD, T2} = parse_const_decl(T),
            parse_decls(T2, Types, Maps, [CD | Consts], Fns);
        fn_kw ->
            {FD, T2} = parse_fn_decl(T),
            parse_decls(T2, Types, Maps, Consts, [FD | Fns]);
        Other ->
            parse_error({unexpected_in_program, Other}, T)
    end.

%%% ===================================================================
%%% Type declarations
%%% ===================================================================

%% type Name do ... end
parse_type_decl([{token, type_kw, _, L, C} | T]) ->
    {Name, T2} = expect_type_ident(T),
    T3 = skip_newlines(expect_token(do_kw, skip_newlines(T2))),
    {Fields, T4} = parse_fields(T3, []),
    T5 = expect_token(end_kw, skip_newlines(T4)),
    {#type_decl{name = Name, fields = lists:reverse(Fields), loc = {L, C}}, T5}.

parse_fields(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        end_kw -> {Acc, T};
        ident ->
            {FName, T2} = expect_ident(T),
            T3 = expect_token(colon, T2),
            {FType, T4} = parse_type_expr(skip_newlines(T3)),
            parse_fields(T4, [{FName, FType} | Acc]);
        _ -> {Acc, T}
    end.

%%% ===================================================================
%%% Map declarations
%%% ===================================================================

%% map :name, kind, key: Type, value: Type, max_entries: N
parse_map_decl([{token, map_kw, _, L, C} | T]) ->
    {Name, T2} = expect_atom_lit(T),
    T3 = expect_token(comma, T2),
    {Kind, T4} = expect_map_kind(T3),
    T5 = expect_token(comma, T4),
    T6 = expect_ident_value(T5, <<"key">>),
    T7 = expect_token(colon, T6),
    {KeyType, T8} = parse_type_expr(skip_newlines(T7)),
    T9 = expect_token(comma, T8),
    T10 = expect_ident_value(T9, <<"value">>),
    T11 = expect_token(colon, T10),
    {ValType, T12} = parse_type_expr(skip_newlines(T11)),
    T13 = expect_token(comma, T12),
    T14 = expect_ident_value(T13, <<"max_entries">>),
    T15 = expect_token(colon, T14),
    {MaxE, T16} = expect_integer(T15),
    {#map_decl{name = Name, kind = Kind, key_type = KeyType,
               value_type = ValType, max_entries = MaxE, loc = {L, C}}, T16}.

%%% ===================================================================
%%% Const declarations
%%% ===================================================================

%% const NAME : type = expr
parse_const_decl([{token, const_kw, _, L, C} | T]) ->
    {Name, T2} = expect_ident(T),
    T3 = expect_token(colon, T2),
    {Type, T4} = parse_type_expr(skip_newlines(T3)),
    T5 = expect_token(eq, T4),
    {Expr, T6} = parse_expr(skip_newlines(T5)),
    {#const_decl{name = Name, type = Type, value = Expr, loc = {L, C}}, T6}.

%%% ===================================================================
%%% Function declarations
%%% ===================================================================

%% fn name(params) -> ret_type do ... end
parse_fn_decl([{token, fn_kw, _, L, C} | T]) ->
    {Name, T2} = expect_ident(T),
    T3 = expect_token(lparen, T2),
    {Params, T4} = parse_params(T3, []),
    T5 = expect_token(rparen, T4),
    {RetType, T6} = maybe_ret_type(T5),
    T7 = expect_token(do_kw, skip_newlines(T6)),
    T8 = skip_newlines(T7),
    {Body, T9} = parse_stmts(T8),
    T10 = expect_token(end_kw, skip_newlines(T9)),
    {#fn_decl{name = Name, params = lists:reverse(Params),
              ret_type = RetType, body = Body, loc = {L, C}}, T10}.

parse_params(Tokens, Acc) ->
    case peek_type(Tokens) of
        rparen -> {Acc, Tokens};
        _ ->
            {Name, T2} = expect_ident(Tokens),
            {Type, T3} = case peek_type(T2) of
                colon ->
                    T2b = expect_token(colon, T2),
                    {Ty, T2c} = parse_type_expr(T2b),
                    {Ty, T2c};
                _ ->
                    {undefined, T2}
            end,
            case peek_type(T3) of
                comma -> parse_params(tl(T3), [{Name, Type} | Acc]);
                _ -> {[{Name, Type} | Acc], T3}
            end
    end.

maybe_ret_type(Tokens) ->
    case peek_type(Tokens) of
        arrow ->
            T2 = tl(Tokens),
            parse_type_expr(skip_newlines(T2));
        _ ->
            {undefined, Tokens}
    end.

%%% ===================================================================
%%% Statements
%%% ===================================================================

parse_stmts(Tokens) ->
    parse_stmts(Tokens, []).

parse_stmts(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        end_kw -> {lists:reverse(Acc), T};
        else_kw -> {lists:reverse(Acc), T};
        elif_kw -> {lists:reverse(Acc), T};
        eof -> {lists:reverse(Acc), T};
        _ ->
            {Stmt, T2} = parse_stmt(T),
            parse_stmts(T2, [Stmt | Acc])
    end.

parse_stmt(Tokens) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        let_kw    -> parse_let(T);
        if_kw     -> parse_if(T);
        for_kw    -> parse_for(T);
        match_kw  -> parse_match(T);
        return_kw -> parse_return(T);
        break_kw ->
            [{token, _, _, L, C} | T2] = T,
            {{break_stmt, {L, C}}, T2};
        continue_kw ->
            [{token, _, _, L, C} | T2] = T,
            {{continue_stmt, {L, C}}, T2};
        _ ->
            parse_expr_or_assign(T)
    end.

parse_let([{token, let_kw, _, L, C} | T]) ->
    {Pat, T2} = parse_pattern(T),
    T3 = case peek_type(T2) of
        colon ->
            T2b = expect_token(colon, T2),
            {_Type, T2c} = parse_type_expr(T2b),
            T2c;
        _ -> T2
    end,
    T4 = expect_token(eq, T3),
    {Expr, T5} = parse_expr(skip_newlines(T4)),
    {{let_stmt, Pat, Expr, {L, C}}, T5}.

parse_if([{token, if_kw, _, L, C} | T]) ->
    {Cond, T2} = parse_expr(T),
    T3 = expect_token(do_kw, skip_newlines(T2)),
    {ThenBody, T4} = parse_stmts(skip_newlines(T3)),
    {Elifs, T5} = parse_elifs(T4, []),
    {ElseBody, T6} = parse_else(T5),
    T7 = expect_token(end_kw, skip_newlines(T6)),
    {{if_stmt, Cond, ThenBody, lists:reverse(Elifs), ElseBody, {L, C}}, T7}.

parse_elifs(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        elif_kw ->
            [_ | T2] = T,
            {Cond, T3} = parse_expr(T2),
            T4 = expect_token(do_kw, skip_newlines(T3)),
            {Body, T5} = parse_stmts(skip_newlines(T4)),
            parse_elifs(T5, [{Cond, Body} | Acc]);
        _ ->
            {Acc, T}
    end.

parse_else(Tokens) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        else_kw ->
            [_ | T2] = T,
            T3 = skip_newlines(T2),
            %% else can have optional do
            T4 = case peek_type(T3) of
                do_kw -> tl(T3);
                _ -> T3
            end,
            parse_stmts(skip_newlines(T4));
        _ ->
            {[], T}
    end.

parse_for([{token, for_kw, _, L, C} | T]) ->
    {VarName, T2} = expect_ident(T),
    T3 = expect_token(in_kw, T2),
    {FromExpr, T4} = parse_expr(T3),
    %% expect .. or ..=
    {Inclusive, T5} = case peek_type(T4) of
        dotdoteq -> {true, tl(T4)};
        dotdot   -> {false, tl(T4)};
        _ -> parse_error(expected_range_op, T4)
    end,
    {ToExpr0, T6} = parse_expr(T5),
    ToExpr = case Inclusive of
        true -> {binop, '+', ToExpr0, {integer_lit, 1, {0,0}}, {0,0}};
        false -> ToExpr0
    end,
    T7 = expect_token(do_kw, skip_newlines(T6)),
    {Body, T8} = parse_stmts(skip_newlines(T7)),
    T9 = expect_token(end_kw, skip_newlines(T8)),
    {{for_stmt, VarName, FromExpr, ToExpr, Body, {L, C}}, T9}.

parse_match([{token, match_kw, _, L, C} | T]) ->
    {Expr, T2} = parse_expr(T),
    T3 = expect_token(do_kw, skip_newlines(T2)),
    {Arms, T4} = parse_match_arms(skip_newlines(T3), []),
    T5 = expect_token(end_kw, skip_newlines(T4)),
    {{match_stmt, Expr, lists:reverse(Arms), {L, C}}, T5}.

parse_match_arms(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        end_kw -> {Acc, T};
        _ ->
            {Pat, T2} = parse_pattern(T),
            T3 = expect_token(arrow, T2),
            {Body, T4} = case peek_type(skip_newlines(T3)) of
                do_kw ->
                    T3b = expect_token(do_kw, skip_newlines(T3)),
                    {B, T3c} = parse_stmts(skip_newlines(T3b)),
                    T3d = expect_token(end_kw, skip_newlines(T3c)),
                    {B, T3d};
                _ ->
                    {S, T3b} = parse_stmt(skip_newlines(T3)),
                    {[S], T3b}
            end,
            parse_match_arms(T4, [{Pat, Body} | Acc])
    end.

parse_return([{token, return_kw, _, L, C} | T]) ->
    T2 = skip_newlines(T),
    case peek_type(T2) of
        newline -> {{return_stmt, {integer_lit, 0, {L, C}}, {L, C}}, T2};
        end_kw -> {{return_stmt, {integer_lit, 0, {L, C}}, {L, C}}, T2};
        eof -> {{return_stmt, {integer_lit, 0, {L, C}}, {L, C}}, T2};
        _ ->
            {Expr, T3} = parse_expr(T2),
            {{return_stmt, Expr, {L, C}}, T3}
    end.

parse_expr_or_assign(Tokens) ->
    {Expr, T2} = parse_expr(Tokens),
    case peek_type(T2) of
        eq ->
            [{token, _, _, L, C} | T3] = T2,
            {RHS, T4} = parse_expr(skip_newlines(T3)),
            {{assign_stmt, Expr, RHS, {L, C}}, T4};
        _ ->
            Loc = expr_loc(Expr),
            {{expr_stmt, Expr, Loc}, T2}
    end.

%%% ===================================================================
%%% Expressions — Pratt precedence climbing
%%% ===================================================================

parse_expr(Tokens) ->
    parse_prec(Tokens, 2).

%% Precedence levels:
%% 2: || (or)
%% 3: && (and)
%% 4: | (bitwise or)
%% 5: ^ (xor)
%% 6: & (bitwise and)
%% 7: == != (equality)
%% 8: < > <= >= (comparison)
%% 9: << >> (shift)
%% 10: + - (additive)
%% 11: * / % (multiplicative)
%% 12: unary prefix
%% 13: postfix

parse_prec(Tokens, Level) when Level > 11 ->
    parse_unary(Tokens);
parse_prec(Tokens, Level) ->
    {Left, T2} = parse_prec(Tokens, Level + 1),
    parse_prec_loop(Left, T2, Level).

parse_prec_loop(Left, Tokens, Level) ->
    case peek_binop(Tokens, Level) of
        {ok, Op, T2} ->
            {Right, T3} = parse_prec(T2, Level + 1),
            Loc = expr_loc(Left),
            NewLeft = {binop, Op, Left, Right, Loc},
            parse_prec_loop(NewLeft, T3, Level);
        none ->
            {Left, Tokens}
    end.

peek_binop(Tokens, Level) ->
    case peek_type(Tokens) of
        or_or     when Level =:= 2  -> {ok, '||', tl(Tokens)};
        and_and   when Level =:= 3  -> {ok, '&&', tl(Tokens)};
        pipe_op   when Level =:= 4  -> {ok, '|', tl(Tokens)};
        caret     when Level =:= 5  -> {ok, '^', tl(Tokens)};
        ampersand when Level =:= 6  -> {ok, '&', tl(Tokens)};
        eq_eq     when Level =:= 7  -> {ok, '==', tl(Tokens)};
        bang_eq   when Level =:= 7  -> {ok, '!=', tl(Tokens)};
        lt        when Level =:= 8  -> {ok, '<', tl(Tokens)};
        gt        when Level =:= 8  -> {ok, '>', tl(Tokens)};
        lt_eq     when Level =:= 8  -> {ok, '<=', tl(Tokens)};
        gt_eq     when Level =:= 8  -> {ok, '>=', tl(Tokens)};
        lshift    when Level =:= 9  -> {ok, '<<', tl(Tokens)};
        rshift    when Level =:= 9  -> {ok, '>>', tl(Tokens)};
        plus      when Level =:= 10 -> {ok, '+', tl(Tokens)};
        minus     when Level =:= 10 -> {ok, '-', tl(Tokens)};
        star      when Level =:= 11 -> {ok, '*', tl(Tokens)};
        slash     when Level =:= 11 -> {ok, '/', tl(Tokens)};
        percent   when Level =:= 11 -> {ok, '%', tl(Tokens)};
        _ -> none
    end.

%% Unary prefix: -, !, ~
parse_unary(Tokens) ->
    case peek_type(Tokens) of
        minus ->
            [{token, _, _, L, C} | T2] = Tokens,
            {Expr, T3} = parse_unary(T2),
            {{unop, '-', Expr, {L, C}}, T3};
        bang ->
            [{token, _, _, L, C} | T2] = Tokens,
            {Expr, T3} = parse_unary(T2),
            {{unop, '!', Expr, {L, C}}, T3};
        tilde ->
            [{token, _, _, L, C} | T2] = Tokens,
            {Expr, T3} = parse_unary(T2),
            {{unop, '~', Expr, {L, C}}, T3};
        _ ->
            parse_postfix(Tokens)
    end.

%% Postfix: .field, [idx], (args), ?.field
parse_postfix(Tokens) ->
    {Prim, T2} = parse_primary(Tokens),
    parse_postfix_loop(Prim, T2).

parse_postfix_loop(Expr, Tokens) ->
    case peek_type(Tokens) of
        dot ->
            [_ | T2] = Tokens,
            {Field, T3} = expect_ident(T2),
            %% Check if method call: field followed by (
            case peek_type(T3) of
                lparen ->
                    [_ | T4] = T3,
                    {Args, T5} = parse_args(T4, []),
                    T6 = expect_token(rparen, T5),
                    Loc = expr_loc(Expr),
                    parse_postfix_loop({method_call, Expr, Field, Args, Loc}, T6);
                _ ->
                    Loc = expr_loc(Expr),
                    parse_postfix_loop({field_access, Expr, Field, Loc}, T3)
            end;
        lbracket ->
            [_ | T2] = Tokens,
            {IdxExpr, T3} = parse_expr(T2),
            T4 = expect_token(rbracket, T3),
            Loc = expr_loc(Expr),
            parse_postfix_loop({index, Expr, IdxExpr, Loc}, T4);
        _ ->
            {Expr, Tokens}
    end.

%% Primary expressions
parse_primary(Tokens) ->
    case Tokens of
        [{token, integer_lit, Val, L, C} | T] ->
            {{integer_lit, Val, {L, C}}, T};
        [{token, true_kw, _, L, C} | T] ->
            {{bool_lit, true, {L, C}}, T};
        [{token, false_kw, _, L, C} | T] ->
            {{bool_lit, false, {L, C}}, T};
        [{token, atom_lit, Val, L, C} | T] ->
            {{atom_lit, Val, {L, C}}, T};
        [{token, none_kw, _, L, C} | T] ->
            {{none_expr, {L, C}}, T};
        [{token, some_kw, _, L, C} | T] ->
            T2 = expect_token(lparen, T),
            {Expr, T3} = parse_expr(T2),
            T4 = expect_token(rparen, T3),
            {{some_expr, Expr, {L, C}}, T4};
        [{token, sizeof_kw, _, L, C} | T] ->
            T2 = expect_token(lparen, T),
            {TypeE, T3} = parse_type_expr(T2),
            T4 = expect_token(rparen, T3),
            {{sizeof_expr, TypeE, {L, C}}, T4};
        [{token, lparen, _, _, _} | T] ->
            {Expr, T2} = parse_expr(T),
            T3 = expect_token(rparen, T2),
            {Expr, T3};
        [{token, percent, _, L, C} | T] ->
            %% Struct literal: %Type{field: val, ...}
            {TypeName, T2} = expect_type_ident(T),
            T3 = expect_token(lbrace, T2),
            {Fields, T4} = parse_struct_fields(T3, []),
            T5 = expect_token(rbrace, T4),
            {{struct_lit, TypeName, lists:reverse(Fields), {L, C}}, T5};
        [{token, type_ident, Name, L, C} | T] ->
            %% Could be a type name used as value (constructor-ish)
            {{var, Name, {L, C}}, T};
        [{token, ident, Name, L, C} | T] ->
            %% Check if function call
            case peek_type(T) of
                lparen ->
                    [_ | T2] = T,
                    {Args, T3} = parse_args(T2, []),
                    T4 = expect_token(rparen, T3),
                    {{call, Name, Args, {L, C}}, T4};
                _ ->
                    {{var, Name, {L, C}}, T}
            end;
        _ ->
            parse_error({unexpected_token, peek_type(Tokens)}, Tokens)
    end.

parse_args(Tokens, Acc) ->
    case peek_type(Tokens) of
        rparen -> {lists:reverse(Acc), Tokens};
        _ ->
            {Expr, T2} = parse_expr(Tokens),
            case peek_type(T2) of
                comma -> parse_args(tl(T2), [Expr | Acc]);
                _ -> {lists:reverse([Expr | Acc]), T2}
            end
    end.

parse_struct_fields(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        rbrace -> {Acc, T};
        _ ->
            {FName, T2} = expect_ident(T),
            T3 = expect_token(colon, T2),
            {FExpr, T4} = parse_expr(skip_newlines(T3)),
            T5 = skip_newlines(T4),
            T6 = case peek_type(T5) of
                comma -> tl(T5);
                _ -> T5
            end,
            parse_struct_fields(T6, [{FName, FExpr} | Acc])
    end.

%%% ===================================================================
%%% Patterns
%%% ===================================================================

parse_pattern(Tokens) ->
    case Tokens of
        [{token, ident, <<"_">>, _, _} | T] ->
            {{wildcard}, T};
        [{token, ident, Name, _, _} | T] ->
            {{var_pat, Name}, T};
        [{token, some_kw, _, _, _} | T] ->
            T2 = expect_token(lparen, T),
            {InnerPat, T3} = parse_pattern(T2),
            T4 = expect_token(rparen, T3),
            {{some_pat, InnerPat}, T4};
        [{token, none_kw, _, _, _} | T] ->
            {{none_pat}, T};
        [{token, integer_lit, Val, _, _} | T] ->
            {{lit_pat, Val}, T};
        [{token, true_kw, _, _, _} | T] ->
            {{lit_pat, true}, T};
        [{token, false_kw, _, _, _} | T] ->
            {{lit_pat, false}, T};
        [{token, atom_lit, Val, _, _} | T] ->
            {{lit_pat, Val}, T};
        [{token, percent, _, _, _} | T] ->
            {TypeName, T2} = expect_type_ident(T),
            T3 = expect_token(lbrace, T2),
            {Fields, T4} = parse_pat_fields(T3, []),
            T5 = expect_token(rbrace, T4),
            {{struct_pat, TypeName, lists:reverse(Fields)}, T5};
        _ ->
            parse_error({unexpected_pattern, peek_type(Tokens)}, Tokens)
    end.

parse_pat_fields(Tokens, Acc) ->
    T = skip_newlines(Tokens),
    case peek_type(T) of
        rbrace -> {Acc, T};
        _ ->
            {FName, T2} = expect_ident(T),
            T3 = expect_token(colon, T2),
            {FPat, T4} = parse_pattern(T3),
            T5 = case peek_type(T4) of
                comma -> tl(T4);
                _ -> T4
            end,
            parse_pat_fields(T5, [{FName, FPat} | Acc])
    end.

%%% ===================================================================
%%% Type expressions
%%% ===================================================================

parse_type_expr(Tokens) ->
    case Tokens of
        [{token, u8_kw, _, _, _} | T]     -> {{prim, u8}, T};
        [{token, u16_kw, _, _, _} | T]    -> {{prim, u16}, T};
        [{token, u32_kw, _, _, _} | T]    -> {{prim, u32}, T};
        [{token, u64_kw, _, _, _} | T]    -> {{prim, u64}, T};
        [{token, i8_kw, _, _, _} | T]     -> {{prim, i8}, T};
        [{token, i16_kw, _, _, _} | T]    -> {{prim, i16}, T};
        [{token, i32_kw, _, _, _} | T]    -> {{prim, i32}, T};
        [{token, i64_kw, _, _, _} | T]    -> {{prim, i64}, T};
        [{token, bool_kw, _, _, _} | T]   -> {{prim, bool}, T};
        [{token, action_kw, _, _, _} | T] -> {{prim, action}, T};
        [{token, type_ident, Name, _, _} | T] -> {{named, Name}, T};
        [{token, ident, Name, _, _} | T] -> {{named, Name}, T};
        _ -> parse_error({expected_type, peek_type(Tokens)}, Tokens)
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

peek_type([{token, Type, _, _, _} | _]) -> Type;
peek_type([]) -> eof.

skip_newlines([{token, newline, _, _, _} | T]) -> skip_newlines(T);
skip_newlines(T) -> T.

expect_token(Type, [{token, Type, _, _, _} | T]) -> T;
expect_token(Expected, Tokens) ->
    parse_error({expected, Expected, got, peek_type(Tokens)}, Tokens).

expect_ident([{token, ident, Name, _, _} | T]) -> {Name, T};
expect_ident([{token, type_ident, Name, _, _} | T]) -> {Name, T};
expect_ident(Tokens) -> parse_error({expected_ident, peek_type(Tokens)}, Tokens).

expect_type_ident([{token, type_ident, Name, _, _} | T]) -> {Name, T};
expect_type_ident(Tokens) -> parse_error({expected_type_ident, peek_type(Tokens)}, Tokens).

expect_atom_lit([{token, atom_lit, Name, _, _} | T]) -> {Name, T};
expect_atom_lit(Tokens) -> parse_error({expected_atom, peek_type(Tokens)}, Tokens).

expect_integer([{token, integer_lit, Val, _, _} | T]) -> {Val, T};
expect_integer(Tokens) -> parse_error({expected_integer, peek_type(Tokens)}, Tokens).

expect_ident_value([{token, ident, Expected, _, _} | T], Expected) -> T;
expect_ident_value(Tokens, Expected) ->
    parse_error({expected_ident, Expected, got, peek_type(Tokens)}, Tokens).

expect_prog_type([{token, xdp_kw, _, _, _} | T])    -> {xdp, T};
expect_prog_type([{token, tc_kw, _, _, _} | T])     -> {tc, T};
expect_prog_type([{token, cgroup_kw, _, _, _} | T]) -> {cgroup, T};
expect_prog_type([{token, socket_kw, _, _, _} | T]) -> {socket, T};
expect_prog_type(Tokens) -> parse_error({expected_prog_type, peek_type(Tokens)}, Tokens).

expect_map_kind([{token, hash_kw, _, _, _} | T])           -> {hash, T};
expect_map_kind([{token, array_kw, _, _, _} | T])          -> {array, T};
expect_map_kind([{token, lru_hash_kw, _, _, _} | T])       -> {lru_hash, T};
expect_map_kind([{token, percpu_hash_kw, _, _, _} | T])    -> {percpu_hash, T};
expect_map_kind([{token, percpu_array_kw, _, _, _} | T])   -> {percpu_array, T};
expect_map_kind([{token, lru_percpu_hash_kw, _, _, _} | T]) -> {lru_percpu_hash, T};
expect_map_kind([{token, ringbuf_kw, _, _, _} | T])        -> {ringbuf, T};
expect_map_kind([{token, devmap_hash_kw, _, _, _} | T])    -> {devmap_hash, T};
expect_map_kind([{token, prog_array_kw, _, _, _} | T])     -> {prog_array, T};
expect_map_kind(Tokens) -> parse_error({expected_map_kind, peek_type(Tokens)}, Tokens).

maybe_direction(Tokens) ->
    case peek_type(Tokens) of
        comma ->
            [_ | T2] = Tokens,
            case T2 of
                [{token, atom_lit, <<"ingress">>, _, _} | T3] -> {ingress, T3};
                [{token, atom_lit, <<"egress">>, _, _} | T3] -> {egress, T3};
                _ -> parse_error(expected_direction, T2)
            end;
        _ ->
            {undefined, Tokens}
    end.

expr_loc({_, _, Loc}) -> Loc;
expr_loc({_, _, _, Loc}) -> Loc;
expr_loc({_, _, _, _, Loc}) -> Loc;
expr_loc(_) -> {0, 0}.

-spec parse_error(term(), list()) -> no_return().
parse_error(Reason, [{token, _, _, L, C} | _]) ->
    throw({parse_error, {Reason, {L, C}}});
parse_error(Reason, _) ->
    throw({parse_error, {Reason, {0, 0}}}).
