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

-module(ebl_typecheck).
-moduledoc """
EBL type checker.

Walks the AST and annotates/validates types. Returns a typed AST
(same structure, but with type info attached) or a list of errors.
""".

-include("ebl_ast.hrl").
-include("ebpf_ir.hrl").

-export([check/1]).

-record(env, {
    prog_type :: xdp | tc | cgroup | socket,
    structs = #{} :: #{binary() => [{binary(), ir_type()}]},
    maps = #{} :: #{binary() => {atom(), ir_type(), ir_type(), non_neg_integer()}},
    consts = #{} :: #{binary() => ir_type()},
    locals = #{} :: #{binary() => ir_type()},
    fns = #{} :: #{binary() => {[ir_type()], ir_type()}},
    errors = [] :: [term()]
}).

-doc "Type-check a parsed program. Returns {ok, TypedProgram} | {error, Errors}.".
-spec check(#program{}) -> {ok, #program{}} | {error, [term()]}.
check(#program{} = Prog) ->
    Env0 = init_env(Prog),
    Env1 = register_types(Prog#program.types, Env0),
    Env2 = register_maps(Prog#program.maps, Env1),
    Env3 = register_consts(Prog#program.consts, Env2),
    Env4 = register_fns(Prog#program.fns, Env3),
    Env5 = check_fns(Prog#program.fns, Env4),
    case Env5#env.errors of
        [] -> {ok, Prog};
        Errs -> {error, lists:reverse(Errs)}
    end.

%%% ===================================================================
%%% Environment initialization
%%% ===================================================================

init_env(#program{type = PT}) ->
    #env{prog_type = PT}.

register_types([], Env) ->
    Env;
register_types([#type_decl{name = Name, fields = Fields} | Rest], Env) ->
    TypedFields = [{FN, ast_type_to_ir(FT)} || {FN, FT} <- Fields],
    Env2 = Env#env{structs = (Env#env.structs)#{Name => TypedFields}},
    register_types(Rest, Env2).

register_maps([], Env) ->
    Env;
register_maps(
    [
        #map_decl{
            name = Name,
            kind = Kind,
            key_type = KT,
            value_type = VT,
            max_entries = Max
        }
        | Rest
    ],
    Env
) ->
    Env2 = Env#env{
        maps = (Env#env.maps)#{Name => {Kind, ast_type_to_ir(KT), ast_type_to_ir(VT), Max}}
    },
    register_maps(Rest, Env2).

register_consts([], Env) ->
    Env;
register_consts([#const_decl{name = Name, type = Type} | Rest], Env) ->
    Env2 = Env#env{consts = (Env#env.consts)#{Name => ast_type_to_ir(Type)}},
    register_consts(Rest, Env2).

register_fns([], Env) ->
    Env;
register_fns([#fn_decl{name = Name, params = Params, ret_type = RT} | Rest], Env) ->
    ParamTypes = [
        case PT of
            undefined -> {scalar, u64};
            _ -> ast_type_to_ir(PT)
        end
     || {_, PT} <- Params
    ],
    RetType =
        case RT of
            undefined -> {scalar, u64};
            _ -> ast_type_to_ir(RT)
        end,
    Env2 = Env#env{fns = (Env#env.fns)#{Name => {ParamTypes, RetType}}},
    register_fns(Rest, Env2).

%%% ===================================================================
%%% Function body checking
%%% ===================================================================

check_fns([], Env) ->
    Env;
check_fns([#fn_decl{params = Params, body = Body} | Rest], Env) ->
    %% Push params into local scope
    %% First parameter with undefined type is the BPF context pointer
    {_, Locals} = lists:foldl(
        fun({PName, PT}, {IsFirst, Acc}) ->
            T =
                case {PT, IsFirst} of
                    {undefined, true} -> {ptr, ctx};
                    {undefined, false} -> {scalar, u64};
                    {_, _} -> ast_type_to_ir(PT)
                end,
            {false, Acc#{PName => T}}
        end,
        {true, #{}},
        Params
    ),
    Env2 = Env#env{locals = Locals},
    Env3 = check_stmts(Body, Env2),
    %% Restore locals
    Env4 = Env3#env{locals = Env#env.locals},
    check_fns(Rest, Env4).

%%% ===================================================================
%%% Statement checking
%%% ===================================================================

check_stmts([], Env) ->
    Env;
check_stmts([Stmt | Rest], Env) ->
    Env2 = check_stmt(Stmt, Env),
    check_stmts(Rest, Env2).

check_stmt({let_stmt, Pat, Expr, Loc}, Env) ->
    {ExprType, Env2} = infer_expr(Expr, Env),
    bind_pattern(Pat, ExprType, Loc, Env2);
check_stmt({assign_stmt, LHS, RHS, Loc}, Env) ->
    {LType, Env2} = infer_expr(LHS, Env),
    {RType, Env3} = infer_expr(RHS, Env2),
    case types_compatible(LType, RType) of
        true -> Env3;
        false -> add_error({type_mismatch, LType, RType, Loc}, Env3)
    end;
check_stmt({if_stmt, Cond, Then, Elifs, Else, _Loc}, Env) ->
    {CondT, Env2} = infer_expr(Cond, Env),
    Env3 = expect_bool(CondT, Cond, Env2),
    Env4 = check_stmts(Then, Env3),
    Env5 = lists:foldl(
        fun({ECond, EBody}, E) ->
            {ET, E2} = infer_expr(ECond, E),
            E3 = expect_bool(ET, ECond, E2),
            check_stmts(EBody, E3)
        end,
        Env4,
        Elifs
    ),
    check_stmts(Else, Env5);
check_stmt({for_stmt, VarName, From, To, Body, Loc}, Env) ->
    {FromT, Env2} = infer_expr(From, Env),
    {ToT, Env3} = infer_expr(To, Env2),
    Env4 =
        case is_integer_type(FromT) andalso is_integer_type(ToT) of
            true -> Env3;
            false -> add_error({for_bounds_not_integer, Loc}, Env3)
        end,
    %% Check that bounds are compile-time evaluable (simplified: just check they exist)
    Env5 = Env4#env{locals = (Env4#env.locals)#{VarName => FromT}},
    Env6 = check_stmts(Body, Env5),
    Env6#env{locals = maps:remove(VarName, Env6#env.locals)};
check_stmt({match_stmt, Expr, Arms, _Loc}, Env) ->
    {_ExprType, Env2} = infer_expr(Expr, Env),
    lists:foldl(
        fun({Pat, ArmBody}, E) ->
            E2 = bind_pattern(Pat, _ExprType, {0, 0}, E),
            check_stmts(ArmBody, E2)
        end,
        Env2,
        Arms
    );
check_stmt({return_stmt, Expr, _Loc}, Env) ->
    {_RetType, Env2} = infer_expr(Expr, Env),
    Env2;
check_stmt({break_stmt, _Loc}, Env) ->
    Env;
check_stmt({continue_stmt, _Loc}, Env) ->
    Env;
check_stmt({expr_stmt, Expr, _Loc}, Env) ->
    {_Type, Env2} = infer_expr(Expr, Env),
    Env2.

%%% ===================================================================
%%% Expression type inference
%%% ===================================================================

infer_expr({integer_lit, _, _}, Env) ->
    {{scalar, u64}, Env};
infer_expr({bool_lit, _, _}, Env) ->
    {{scalar, bool}, Env};
infer_expr({atom_lit, Name, Loc}, Env) ->
    case action_type(Name, Env#env.prog_type) of
        {ok, _Val} -> {action, Env};
        error -> {action, add_error({invalid_action, Name, Env#env.prog_type, Loc}, Env)}
    end;
infer_expr({var, Name, Loc}, Env) ->
    case maps:find(Name, Env#env.locals) of
        {ok, T} ->
            {T, Env};
        error ->
            case maps:find(Name, Env#env.consts) of
                {ok, T} ->
                    {T, Env};
                error ->
                    %% Check if it's a map name (used as reference in map ops)
                    case maps:is_key(Name, Env#env.maps) of
                        true -> {{scalar, u64}, Env};
                        false -> {{scalar, u64}, add_error({undefined_var, Name, Loc}, Env)}
                    end
            end
    end;
infer_expr({binop, Op, Left, Right, Loc}, Env) ->
    {LT, Env2} = infer_expr(Left, Env),
    {RT, Env3} = infer_expr(Right, Env2),
    case is_comparison_op(Op) of
        true ->
            Env4 =
                case types_compatible(LT, RT) of
                    true -> Env3;
                    false -> add_error({type_mismatch, LT, RT, Loc}, Env3)
                end,
            {{scalar, bool}, Env4};
        false ->
            case is_logical_op(Op) of
                true ->
                    Env4 = expect_bool(LT, Left, Env3),
                    Env5 = expect_bool(RT, Right, Env4),
                    {{scalar, bool}, Env5};
                false ->
                    %% Arithmetic: reject bool operands (bool + u32 is nonsense)
                    Env4 =
                        case LT of
                            {scalar, bool} -> add_error({bool_in_arithmetic, Op, Left, Loc}, Env3);
                            _ -> Env3
                        end,
                    Env5 =
                        case RT of
                            {scalar, bool} -> add_error({bool_in_arithmetic, Op, Right, Loc}, Env4);
                            _ -> Env4
                        end,
                    ResultT = wider_type(LT, RT),
                    {ResultT, Env5}
            end
    end;
infer_expr({unop, '!', Expr, _Loc}, Env) ->
    {ET, Env2} = infer_expr(Expr, Env),
    Env3 = expect_bool(ET, Expr, Env2),
    {{scalar, bool}, Env3};
infer_expr({unop, '-', Expr, _Loc}, Env) ->
    {ET, Env2} = infer_expr(Expr, Env),
    {ET, Env2};
infer_expr({unop, '~', Expr, _Loc}, Env) ->
    {ET, Env2} = infer_expr(Expr, Env),
    {ET, Env2};
infer_expr({call, Name, Args, Loc}, Env) ->
    {ArgTypes, Env2} = infer_exprs(Args, Env),
    case is_map_builtin(Name) of
        {true, RetType} ->
            {RetType, Env2};
        false ->
            case maps:find(Name, Env2#env.fns) of
                {ok, {ParamTypes, RetType}} ->
                    Env3 = check_arg_count(Name, length(ParamTypes), length(ArgTypes), Loc, Env2),
                    {RetType, Env3};
                error ->
                    {{scalar, u64}, add_error({undefined_fn, Name, Loc}, Env2)}
            end
    end;
infer_expr({method_call, Obj, Method, Args, Loc}, Env) ->
    {ObjType, Env2} = infer_expr(Obj, Env),
    infer_method(ObjType, Obj, Method, Args, Loc, Env2);
infer_expr({field_access, Obj, Field, Loc}, Env) ->
    {ObjType, Env2} = infer_expr(Obj, Env),
    infer_field(ObjType, Field, Loc, Env2);
infer_expr({index, Obj, Idx, _Loc}, Env) ->
    {_ObjType, Env2} = infer_expr(Obj, Env),
    {_IdxType, Env3} = infer_expr(Idx, Env2),
    {{scalar, u64}, Env3};
infer_expr({struct_lit, TypeName, Fields, Loc}, Env) ->
    case maps:find(TypeName, Env#env.structs) of
        {ok, _StructFields} ->
            Env2 = lists:foldl(
                fun({_FN, FExpr}, E) ->
                    {_, E2} = infer_expr(FExpr, E),
                    E2
                end,
                Env,
                Fields
            ),
            {{named, TypeName}, Env2};
        error ->
            {{named, TypeName}, add_error({undefined_type, TypeName, Loc}, Env)}
    end;
infer_expr({sizeof_expr, _TypeExpr, _Loc}, Env) ->
    {{scalar, u64}, Env};
infer_expr({some_expr, Inner, _Loc}, Env) ->
    {IT, Env2} = infer_expr(Inner, Env),
    {{option, IT}, Env2};
infer_expr({none_expr, _Loc}, Env) ->
    {{option, {scalar, u64}}, Env};
infer_expr({if_expr, Cond, Then, Else, _Loc}, Env) ->
    {CondT, Env2} = infer_expr(Cond, Env),
    Env3 = expect_bool(CondT, Cond, Env2),
    {ThenT, Env4} = infer_expr(Then, Env3),
    {_ElseT, Env5} = infer_expr(Else, Env4),
    {ThenT, Env5};
infer_expr(_, Env) ->
    {{scalar, u64}, Env}.

%%% ===================================================================
%%% Method inference (map operations)
%%% ===================================================================

infer_method(_ObjType, Obj, <<"lookup">>, _Args, _Loc, Env) ->
    %% map.lookup(key) → option<ptr<value_type>>
    case map_type_from_expr(Obj, Env) of
        {ok, {_Kind, _KT, _VT, _Max}} ->
            {{option, {ptr, map_value}}, Env};
        error ->
            {{option, {ptr, map_value}}, Env}
    end;
infer_method(_ObjType, _Obj, <<"update">>, Args, _Loc, Env) ->
    {_ArgTypes, Env2} = infer_exprs(Args, Env),
    {{scalar, i64}, Env2};
infer_method(_ObjType, _Obj, <<"delete">>, Args, _Loc, Env) ->
    {_ArgTypes, Env2} = infer_exprs(Args, Env),
    {{scalar, i64}, Env2};
infer_method(_ObjType, _Obj, Method, Args, Loc, Env) ->
    case is_cast_method(Method) of
        true ->
            {{scalar, u64}, add_error({unsupported_cast, Method, Loc}, Env)};
        false ->
            {_ArgTypes, Env2} = infer_exprs(Args, Env),
            {{scalar, u64}, Env2}
    end.

%% Detect cast method calls like as_u32(), as_u64(), etc. which are not implemented.
is_cast_method(<<"as_u8">>) -> true;
is_cast_method(<<"as_u16">>) -> true;
is_cast_method(<<"as_u32">>) -> true;
is_cast_method(<<"as_u64">>) -> true;
is_cast_method(<<"as_i8">>) -> true;
is_cast_method(<<"as_i16">>) -> true;
is_cast_method(<<"as_i32">>) -> true;
is_cast_method(<<"as_i64">>) -> true;
is_cast_method(_) -> false.

%%% ===================================================================
%%% Field inference
%%% ===================================================================

infer_field({named, TypeName}, Field, Loc, Env) ->
    case maps:find(TypeName, Env#env.structs) of
        {ok, Fields} ->
            case lists:keyfind(Field, 1, Fields) of
                {_, FType} -> {FType, Env};
                false -> {{scalar, u64}, add_error({unknown_field, TypeName, Field, Loc}, Env)}
            end;
        error ->
            {{scalar, u64}, add_error({undefined_type, TypeName, Loc}, Env)}
    end;
infer_field({ptr, ctx}, Field, Loc, Env) ->
    %% Validate context field against the program type layout
    case ebpf_ctx:field(Env#env.prog_type, Field) of
        {ok, _Offset, Size} when Size =< 4 -> {{scalar, u32}, Env};
        {ok, _Offset, _Size} ->
            {{scalar, u64}, Env};
        {error, unknown_field} ->
            {{scalar, u32}, add_error({unknown_ctx_field, Field, Env#env.prog_type, Loc}, Env)}
    end;
infer_field(_, _Field, _Loc, Env) ->
    {{scalar, u64}, Env}.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

infer_exprs(Exprs, Env) ->
    lists:foldl(
        fun(E, {Types, Ev}) ->
            {T, Ev2} = infer_expr(E, Ev),
            {Types ++ [T], Ev2}
        end,
        {[], Env},
        Exprs
    ).

bind_pattern({var_pat, Name}, Type, _Loc, Env) ->
    Env#env{locals = (Env#env.locals)#{Name => Type}};
bind_pattern({wildcard}, _Type, _Loc, Env) ->
    Env;
bind_pattern({some_pat, Inner}, {option, InnerType}, Loc, Env) ->
    bind_pattern(Inner, InnerType, Loc, Env);
bind_pattern({some_pat, Inner}, Type, Loc, Env) ->
    bind_pattern(Inner, Type, Loc, Env);
bind_pattern({none_pat}, _Type, _Loc, Env) ->
    Env;
bind_pattern({lit_pat, _}, _Type, _Loc, Env) ->
    Env;
bind_pattern({struct_pat, _TypeName, Fields}, _Type, Loc, Env) ->
    lists:foldl(
        fun({_FN, FPat}, E) ->
            bind_pattern(FPat, {scalar, u64}, Loc, E)
        end,
        Env,
        Fields
    ).

ast_type_to_ir({prim, T}) -> {scalar, T};
ast_type_to_ir({named, N}) -> {named, N};
ast_type_to_ir({array_type, _ET, _Size}) -> {scalar, u64};
ast_type_to_ir(action) -> action.

types_compatible(T, T) ->
    true;
types_compatible({scalar, A}, {scalar, B}) ->
    is_integer_type({scalar, A}) andalso is_integer_type({scalar, B});
types_compatible(action, {scalar, _}) ->
    true;
types_compatible({scalar, _}, action) ->
    true;
types_compatible(_, _) ->
    false.

wider_type({scalar, A}, {scalar, B}) ->
    {scalar, wider_scalar(A, B)};
wider_type(T, _) ->
    T.

%% Return the wider scalar type. When mixing signed/unsigned,
%% return the unsigned variant of the wider width (symmetric).
wider_scalar(A, B) ->
    WA = scalar_width(A),
    WB = scalar_width(B),
    Width = max(WA, WB),
    case {is_unsigned(A), is_unsigned(B)} of
        {true, true} -> unsigned_of_width(Width);
        {false, false} -> signed_of_width(Width);
        %% mixed → unsigned
        _Mixed -> unsigned_of_width(Width)
    end.

scalar_width(u8) -> 8;
scalar_width(i8) -> 8;
scalar_width(u16) -> 16;
scalar_width(i16) -> 16;
scalar_width(u32) -> 32;
scalar_width(i32) -> 32;
scalar_width(u64) -> 64;
scalar_width(i64) -> 64;
scalar_width(bool) -> 1;
scalar_width(_) -> 64.

is_unsigned(u8) -> true;
is_unsigned(u16) -> true;
is_unsigned(u32) -> true;
is_unsigned(u64) -> true;
is_unsigned(bool) -> true;
is_unsigned(_) -> false.

unsigned_of_width(1) -> bool;
unsigned_of_width(8) -> u8;
unsigned_of_width(16) -> u16;
unsigned_of_width(32) -> u32;
unsigned_of_width(_) -> u64.

%% bool promoted to signed → i8
signed_of_width(1) -> i8;
signed_of_width(8) -> i8;
signed_of_width(16) -> i16;
signed_of_width(32) -> i32;
signed_of_width(_) -> i64.

is_integer_type({scalar, T}) ->
    lists:member(T, [u8, u16, u32, u64, i8, i16, i32, i64]);
is_integer_type(_) ->
    false.

is_comparison_op(Op) ->
    lists:member(Op, ['==', '!=', '<', '>', '<=', '>=']).

is_logical_op(Op) ->
    lists:member(Op, ['&&', '||']).

%% Boolean context: accept bool and integer scalars (C-like truthiness).
%% Reject non-scalar types (structs, pointers, options, actions, etc.)
%% to catch semantic errors like using a struct as a condition.
expect_bool({scalar, bool}, _Expr, Env) ->
    Env;
expect_bool({scalar, T}, _Expr, Env) when
    T =:= u8;
    T =:= u16;
    T =:= u32;
    T =:= u64;
    T =:= i8;
    T =:= i16;
    T =:= i32;
    T =:= i64
->
    Env;
expect_bool(Type, Expr, Env) ->
    Loc = expr_loc(Expr),
    add_error({expected_bool, Type, Loc}, Env).

%% Extract location from an expression tuple (last element is Loc in all expr tuples).
expr_loc(Expr) when is_tuple(Expr) ->
    element(tuple_size(Expr), Expr);
expr_loc(_) ->
    {0, 0}.

action_type(<<"drop">>, xdp) -> {ok, 1};
action_type(<<"pass">>, xdp) -> {ok, 2};
action_type(<<"tx">>, xdp) -> {ok, 3};
action_type(<<"redirect">>, xdp) -> {ok, 4};
action_type(<<"aborted">>, xdp) -> {ok, 0};
action_type(<<"ok">>, tc) -> {ok, 0};
action_type(<<"shot">>, tc) -> {ok, 2};
action_type(<<"pipe">>, tc) -> {ok, 3};
action_type(<<"drop">>, tc) -> {ok, 2};
action_type(<<"pass">>, tc) -> {ok, 0};
action_type(<<"allow">>, cgroup) -> {ok, 1};
action_type(<<"deny">>, cgroup) -> {ok, 0};
action_type(<<"pass">>, _) -> {ok, 0};
action_type(<<"drop">>, _) -> {ok, 1};
action_type(_, _) -> error.

check_arg_count(_Name, Expected, Got, _Loc, Env) when Expected =:= Got -> Env;
check_arg_count(Name, Expected, Got, Loc, Env) ->
    add_error({wrong_arg_count, Name, Expected, Got, Loc}, Env).

add_error(Err, #env{errors = Errs} = Env) ->
    Env#env{errors = [Err | Errs]}.

map_type_from_expr({var, Name, _}, Env) ->
    maps:find(Name, Env#env.maps);
map_type_from_expr(_, _Env) ->
    error.

%% Check if a function name is a built-in operation.
%% Returns {true, ReturnType} | false.
is_map_builtin(<<"map_lookup">>) -> {true, {scalar, u64}};
is_map_builtin(<<"lookup">>) -> {true, {scalar, u64}};
is_map_builtin(<<"map_update">>) -> {true, {scalar, u64}};
is_map_builtin(<<"update">>) -> {true, {scalar, u64}};
is_map_builtin(<<"map_delete">>) -> {true, {scalar, u64}};
is_map_builtin(<<"delete">>) -> {true, {scalar, u64}};
%% Packet read built-ins
is_map_builtin(<<"read_u8">>) -> {true, {scalar, u8}};
is_map_builtin(<<"read_u16">>) -> {true, {scalar, u16}};
is_map_builtin(<<"read_u32">>) -> {true, {scalar, u32}};
is_map_builtin(<<"read_u16_be">>) -> {true, {scalar, u16}};
is_map_builtin(<<"read_u32_be">>) -> {true, {scalar, u32}};
is_map_builtin(_) -> false.
