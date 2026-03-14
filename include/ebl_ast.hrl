%% ebl_ast.hrl — AST node records for the EBL parser
-ifndef(EBL_AST_HRL).
-define(EBL_AST_HRL, true).

%% Location: {Line, Col}
-type loc() :: {pos_integer(), non_neg_integer()}.

%% ===================================================================
%% Forward type declarations (needed before records)
%% ===================================================================

-type type_expr() ::
    {prim, u8 | u16 | u32 | u64 | i8 | i16 | i32 | i64 | bool | action} |
    {named, binary()} |
    {array_type, type_expr(), non_neg_integer()}.

-type binop() ::
    '+' | '-' | '*' | '/' | '%' |
    '==' | '!=' | '<' | '>' | '<=' | '>=' |
    '&&' | '||' |
    '&' | '|' | '^' | '<<' | '>>' |
    '..' | '..='.

-type unop() :: '-' | '!' | '~'.

-type pattern() ::
    {var_pat, binary()} |
    {wildcard} |
    {some_pat, pattern()} |
    {none_pat} |
    {lit_pat, integer() | boolean() | binary()} |
    {struct_pat, binary(), [{binary(), pattern()}]}.

-type expr() ::
    {integer_lit, integer(), loc()} |
    {bool_lit, boolean(), loc()} |
    {atom_lit, binary(), loc()} |
    {var, binary(), loc()} |
    {field_access, expr(), binary(), loc()} |
    {index, expr(), expr(), loc()} |
    {call, binary(), [expr()], loc()} |
    {method_call, expr(), binary(), [expr()], loc()} |
    {binop, binop(), expr(), expr(), loc()} |
    {unop, unop(), expr(), loc()} |
    {struct_lit, binary(), [{binary(), expr()}], loc()} |
    {sizeof_expr, type_expr(), loc()} |
    {if_expr, expr(), expr(), expr(), loc()} |
    {some_expr, expr(), loc()} |
    {none_expr, loc()}.

-type stmt() ::
    {let_stmt, pattern(), expr(), loc()} |
    {assign_stmt, expr(), expr(), loc()} |
    {if_stmt, expr(), [stmt()], [{expr(), [stmt()]}], [stmt()], loc()} |
    {for_stmt, binary(), expr(), expr(), [stmt()], loc()} |
    {match_stmt, expr(), [{pattern(), [stmt()]}], loc()} |
    {return_stmt, expr(), loc()} |
    {break_stmt, loc()} |
    {continue_stmt, loc()} |
    {expr_stmt, expr(), loc()}.

%% ===================================================================
%% Declarations (records must come after their field types)
%% ===================================================================

-record(type_decl, {
    name   :: binary(),
    fields :: [{binary(), type_expr()}],
    loc    :: loc()
}).

-record(map_decl, {
    name        :: binary(),
    kind        :: hash | array | lru_hash | percpu_hash |
                   percpu_array | lru_percpu_hash | ringbuf |
                   devmap_hash | prog_array,
    key_type    :: type_expr(),
    value_type  :: type_expr(),
    max_entries :: non_neg_integer(),
    loc         :: loc()
}).

-record(const_decl, {
    name  :: binary(),
    type  :: type_expr(),
    value :: expr(),
    loc   :: loc()
}).

-record(fn_decl, {
    name     :: binary(),
    params   :: [{binary(), type_expr() | undefined}],
    ret_type :: type_expr() | undefined,
    body     :: [stmt()],
    loc      :: loc()
}).

%% ===================================================================
%% Top-level program (after all sub-records)
%% ===================================================================

-record(program, {
    type      :: xdp | tc | cgroup | socket,
    name      :: binary(),
    direction :: undefined | ingress | egress,
    types     = [] :: [#type_decl{}],
    maps      = [] :: [#map_decl{}],
    consts    = [] :: [#const_decl{}],
    fns       = [] :: [#fn_decl{}]
}).

-endif. %% EBL_AST_HRL
