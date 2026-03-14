-module(ebl_compile_test).
-include_lib("eunit/include/eunit.hrl").
-include("ebl_ast.hrl").
-include("ebpf_ir.hrl").

%%% ===================================================================
%%% WP-003 Acceptance: end-to-end compile + VM run
%%% ===================================================================

acceptance_xdp_pass_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :pass\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    ?assert(byte_size(Bin) > 0),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(2, Result).  %% XDP_PASS = 2

acceptance_xdp_drop_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :drop\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).  %% XDP_DROP = 1

%%% ===================================================================
%%% Return literal
%%% ===================================================================

return_literal_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return 42\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Arithmetic
%%% ===================================================================

arithmetic_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 10\n"
            "    let b = 32\n"
            "    return a + b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% If statement
%%% ===================================================================

if_true_drops_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    if true do\n"
            "      return :drop\n"
            "    end\n"
            "    return :pass\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).  %% XDP_DROP = 1

if_false_passes_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    if false do\n"
            "      return :drop\n"
            "    end\n"
            "    return :pass\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(2, Result).  %% XDP_PASS = 2

if_else_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 1\n"
            "    if x do\n"
            "      return 10\n"
            "    else\n"
            "      return 20\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(10, Result).

if_else_false_branch_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 0\n"
            "    if x do\n"
            "      return 10\n"
            "    else\n"
            "      return 20\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(20, Result).

if_no_return_join_test() ->
    %% If-then without return, continues to code after if
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if true do\n"
            "      x = 42\n"
            "    end\n"
            "    return x\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Type checker
%%% ===================================================================

typecheck_valid_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    let x : u32 = 42\n"
            "    return :pass\n"
            "  end\n"
            "end">>,
    {ok, _Tokens} = ebl_lexer:tokenize(Src),
    {ok, AST} = ebl_parser:parse(_Tokens),
    ?assertMatch({ok, _}, ebl_typecheck:check(AST)).

typecheck_invalid_action_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :invalid_action\n"
            "  end\n"
            "end">>,
    {ok, Tokens} = ebl_lexer:tokenize(Src),
    {ok, AST} = ebl_parser:parse(Tokens),
    {error, Errors} = ebl_typecheck:check(AST),
    ?assert(length(Errors) > 0).

%%% ===================================================================
%%% IR generation
%%% ===================================================================

ir_gen_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :pass\n"
            "  end\n"
            "end">>,
    {ok, T} = ebl_lexer:tokenize(Src),
    {ok, AST} = ebl_parser:parse(T),
    {ok, TypedAST} = ebl_typecheck:check(AST),
    IR = ebpf_ir_gen:generate(TypedAST),
    ?assertEqual(xdp, IR#ir_program.prog_type),
    ?assert(maps:size(IR#ir_program.blocks) > 0).

%%% ===================================================================
%%% Codegen
%%% ===================================================================

codegen_produces_valid_binary_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return 0\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    ?assert(byte_size(Bin) > 0),
    %% Must be multiple of 8 bytes
    ?assertEqual(0, byte_size(Bin) rem 8).

%%% ===================================================================
%%% Peephole optimizer
%%% ===================================================================

peephole_redundant_mov_test() ->
    %% mov r1, r1 should be eliminated
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:mov64_reg(1, 1),    %% redundant
        ebpf_insn:exit_insn()
    ]),
    Opt = ebpf_peephole:optimize(Prog),
    ?assert(byte_size(Opt) < byte_size(Prog)).

peephole_idempotent_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    Opt1 = ebpf_peephole:optimize(Prog),
    Opt2 = ebpf_peephole:optimize(Opt1),
    ?assertEqual(Opt1, Opt2).

%%% ===================================================================
%%% Compile errors
%%% ===================================================================

lex_error_test() ->
    ?assertMatch({error, _}, ebl_compile:compile(<<"`">>)).

parse_error_test() ->
    ?assertMatch({error, _}, ebl_compile:compile(<<"42">>)).

%%% ===================================================================
%%% TC program type
%%% ===================================================================

tc_program_test() ->
    Src = <<"tc test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :ok\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).  %% TC_OK = 0

%%% ===================================================================
%%% No peephole option
%%% ===================================================================

no_peephole_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return 1\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    ?assert(byte_size(Bin) > 0).

%%% ===================================================================
%%% Multiple statements
%%% ===================================================================

multi_stmt_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 10\n"
            "    let y = 20\n"
            "    let z = x + y\n"
            "    return z\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(30, Result).

%%% ===================================================================
%%% Variable reassignment
%%% ===================================================================

reassignment_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 1\n"
            "    x = 42\n"
            "    return x\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Nested if
%%% ===================================================================

nested_if_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 1\n"
            "    if x do\n"
            "      let y = 1\n"
            "      if y do\n"
            "        return 99\n"
            "      end\n"
            "    end\n"
            "    return 0\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(99, Result).

%%% ===================================================================
%%% If with outer scope variable
%%% ===================================================================

if_outer_scope_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let result = 0\n"
            "    let flag = 1\n"
            "    if flag do\n"
            "      result = 77\n"
            "    end\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(77, Result).

%%% ===================================================================
%%% Subtraction / comparison operators
%%% ===================================================================

subtraction_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 50\n"
            "    let b = 8\n"
            "    return a - b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

multiplication_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 6\n"
            "    let b = 7\n"
            "    return a * b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% For-loop end-to-end
%%% ===================================================================

for_loop_sum_test() ->
    %% sum(0..5) = 0+1+2+3+4 = 10
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..5 do\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(10, Result).

for_loop_count_test() ->
    %% Count iterations: for i in 0..3 → count = 3
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let count = 0\n"
            "    for i in 0..3 do\n"
            "      count = count + 1\n"
            "    end\n"
            "    return count\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(3, Result).

for_loop_zero_iterations_test() ->
    %% for i in 0..0 → never enters body
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 42\n"
            "    for i in 0..0 do\n"
            "      x = 0\n"
            "    end\n"
            "    return x\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Match end-to-end
%%% ===================================================================

match_literal_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 2\n"
            "    match x do\n"
            "      1 -> return 10\n"
            "      2 -> return 20\n"
            "      _ -> return 99\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(20, Result).

match_wildcard_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 99\n"
            "    match x do\n"
            "      1 -> return 10\n"
            "      _ -> return 77\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(77, Result).

%%% ===================================================================
%%% Register allocator — many variables (spill test)
%%% ===================================================================

many_vars_12_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 1\n"
            "    let b = 2\n"
            "    let c = 3\n"
            "    let d = 4\n"
            "    let e = 5\n"
            "    let f = 6\n"
            "    let g = 7\n"
            "    let h = 8\n"
            "    let i = 9\n"
            "    let j = 10\n"
            "    let k = 11\n"
            "    let l = 12\n"
            "    return a + b + c + d + e + f + g + h + i + j + k + l\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(78, Result).

many_vars_15_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 1\n"
            "    let b = 2\n"
            "    let c = 3\n"
            "    let d = 4\n"
            "    let e = 5\n"
            "    let f = 6\n"
            "    let g = 7\n"
            "    let h = 8\n"
            "    let i = 9\n"
            "    let j = 10\n"
            "    let k = 11\n"
            "    let l = 12\n"
            "    let m = 13\n"
            "    let n = 14\n"
            "    let o = 15\n"
            "    return a + b + c + d + e + f + g + h + i + j + k + l + m + n + o\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(120, Result).

%%% ===================================================================
%%% Comparison operators (WP-005)
%%% ===================================================================

cmp_eq_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x == 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_eq_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x == 3 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_ne_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x != 3 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_ne_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x != 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_gt_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 10\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_gt_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_gt_less_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 3\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_ge_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x >= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_ge_greater_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 10\n"
            "    if x >= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_ge_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 3\n"
            "    if x >= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_lt_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 3\n"
            "    if x < 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_lt_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x < 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_lt_greater_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 10\n"
            "    if x < 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

cmp_le_true_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    if x <= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_le_less_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 3\n"
            "    if x <= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

cmp_le_false_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 10\n"
            "    if x <= 5 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

%% Comparison with two variables (not just var vs literal)
cmp_two_vars_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let a = 10\n"
            "    let b = 20\n"
            "    if a < b do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

%% For-loop still works after comparison changes
for_loop_after_cmp_fix_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(45, Result).

%% Comparison inside loop body
cmp_in_loop_test() ->
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let count = 0\n"
            "    for i in 0..10 do\n"
            "      if i > 5 do\n"
            "        count = count + 1\n"
            "      end\n"
            "    end\n"
            "    return count\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(4, Result).  %% i=6,7,8,9 → 4 iterations

%%% ===================================================================
%%% Context field access (WP-008)
%%% ===================================================================

ctx_data_xdp_test() ->
    %% ctx.data should load from offset 0 (32-bit) in XDP context
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.data\n"
            "  end\n"
            "end">>,
    %% Build XDP context: data=0xDEADBEEF at offset 0
    CtxBin = <<16#DEADBEEF:32/little, 0:32, 0:32, 0:32, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(16#DEADBEEF, Result).

ctx_data_end_xdp_test() ->
    %% ctx.data_end should load from offset 4 (32-bit) in XDP context
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.data_end\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 16#CAFEBABE:32/little, 0:32, 0:32, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(16#CAFEBABE, Result).

ctx_ingress_ifindex_xdp_test() ->
    %% ctx.ingress_ifindex should load from offset 12 (32-bit) in XDP context
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.ingress_ifindex\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 0:32, 0:32, 42:32/little, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(42, Result).

ctx_rx_queue_index_xdp_test() ->
    %% ctx.rx_queue_index should load from offset 16 (32-bit) in XDP context
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.rx_queue_index\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 0:32, 0:32, 0:32, 7:32/little, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(7, Result).

ctx_data_meta_xdp_test() ->
    %% ctx.data_meta should load from offset 8
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.data_meta\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 0:32, 99:32/little, 0:32, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(99, Result).

ctx_egress_ifindex_xdp_test() ->
    %% ctx.egress_ifindex should load from offset 20
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.egress_ifindex\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 0:32, 0:32, 0:32, 0:32, 55:32/little>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(55, Result).

ctx_field_in_expression_test() ->
    %% Use ctx.data in an arithmetic expression
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let d = ctx.data\n"
            "    let e = ctx.data_end\n"
            "    return e - d\n"
            "  end\n"
            "end">>,
    CtxBin = <<100:32/little, 200:32/little, 0:32, 0:32, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(100, Result).

ctx_field_in_comparison_test() ->
    %% Use ctx field in a comparison
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    if ctx.ingress_ifindex == 1 do\n"
            "      return 10\n"
            "    else\n"
            "      return 20\n"
            "    end\n"
            "  end\n"
            "end">>,
    CtxBin = <<0:32, 0:32, 0:32, 1:32/little, 0:32, 0:32>>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{ctx => CtxBin}),
    ?assertEqual(10, Result).

ctx_unknown_field_error_test() ->
    %% ctx.nonexistent should produce a type-check error
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    return ctx.nonexistent\n"
            "  end\n"
            "end">>,
    {ok, Tokens} = ebl_lexer:tokenize(Src),
    {ok, AST} = ebl_parser:parse(Tokens),
    {error, Errors} = ebl_typecheck:check(AST),
    ?assert(length(Errors) > 0),
    %% Check it mentions unknown_ctx_field
    [{unknown_ctx_field, <<"nonexistent">>, xdp, _Loc}] = Errors.

ctx_codegen_ldxw_offset_test() ->
    %% Verify that ctx.data generates ldxw with offset 0
    %% and ctx.ingress_ifindex generates ldxw with offset 12
    Src1 = <<"xdp test do\n"
             "  fn main(ctx) -> u64 do\n"
             "    return ctx.data\n"
             "  end\n"
             "end">>,
    {ok, Bin1} = ebl_compile:compile(Src1, #{peephole => false}),
    %% Decode instructions to verify ldxw is present
    Insns1 = decode_all(Bin1),
    %% Find the ldxw instruction — should have offset 0
    ?assert(lists:any(fun({ldxw, _, _, 0, _}) -> true; (_) -> false end, Insns1)),

    Src2 = <<"xdp test do\n"
             "  fn main(ctx) -> u64 do\n"
             "    return ctx.ingress_ifindex\n"
             "  end\n"
             "end">>,
    {ok, Bin2} = ebl_compile:compile(Src2, #{peephole => false}),
    Insns2 = decode_all(Bin2),
    %% Find the ldxw instruction — should have offset 12
    ?assert(lists:any(fun({ldxw, _, _, 12, _}) -> true; (_) -> false end, Insns2)).

%% Helper to decode all instructions from a BPF binary
decode_all(Bin) ->
    decode_all(Bin, []).
decode_all(<<>>, Acc) ->
    lists:reverse(Acc);
decode_all(Bin, Acc) when byte_size(Bin) >= 16 ->
    %% Try 16-byte instruction first (ld_imm64)
    <<First:8/binary, _/binary>> = Bin,
    case First of
        <<16#18, _:7/binary>> ->
            <<Insn:16/binary, Rest/binary>> = Bin,
            decode_all(Rest, [ebpf_insn:decode(Insn) | Acc]);
        _ ->
            <<Insn:8/binary, Rest/binary>> = Bin,
            decode_all(Rest, [ebpf_insn:decode(Insn) | Acc])
    end;
decode_all(<<Insn:8/binary, Rest/binary>>, Acc) ->
    decode_all(Rest, [ebpf_insn:decode(Insn) | Acc]).

%%% ===================================================================
%%% Elif (WP-010)
%%% ===================================================================

elif_first_branch_test() ->
    %% x=6 > 5, so first branch taken → 1
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 6\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    elif x > 3 do\n"
            "      return 2\n"
            "    else\n"
            "      return 3\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(1, Result).

elif_second_branch_test() ->
    %% x=4, not > 5, but > 3 → 2
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 4\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    elif x > 3 do\n"
            "      return 2\n"
            "    else\n"
            "      return 3\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(2, Result).

elif_else_branch_test() ->
    %% x=1, neither > 5 nor > 3 → 3
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 1\n"
            "    if x > 5 do\n"
            "      return 1\n"
            "    elif x > 3 do\n"
            "      return 2\n"
            "    else\n"
            "      return 3\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(3, Result).

elif_three_branches_test() ->
    %% Three elif branches
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 2\n"
            "    if x == 1 do\n"
            "      return 10\n"
            "    elif x == 2 do\n"
            "      return 20\n"
            "    elif x == 3 do\n"
            "      return 30\n"
            "    else\n"
            "      return 40\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(20, Result).

elif_without_else_test() ->
    %% elif without else (empty else body)
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let result = 0\n"
            "    let x = 4\n"
            "    if x > 10 do\n"
            "      result = 1\n"
            "    elif x > 3 do\n"
            "      result = 2\n"
            "    end\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(2, Result).

elif_no_match_no_else_test() ->
    %% elif without else, nothing matches
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let result = 99\n"
            "    let x = 1\n"
            "    if x > 10 do\n"
            "      result = 1\n"
            "    elif x > 5 do\n"
            "      result = 2\n"
            "    end\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(99, Result).

%%% ===================================================================
%%% Break (WP-010)
%%% ===================================================================

break_in_for_loop_test() ->
    %% sum = 0+1+2+3+4 = 10 (break when i==5)
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      if i == 5 do\n"
            "        break\n"
            "      end\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(10, Result).

nested_loop_test() ->
    %% Nested loops with shared mutable variable (was buggy: spill R5 conflict)
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let s = 0\n"
            "    for i in 0..3 do\n"
            "      for j in 0..3 do\n"
            "        s = s + 1\n"
            "      end\n"
            "    end\n"
            "    return s\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(9, Result).  %% 3 * 3 = 9

break_nested_loop_test() ->
    %% Break only breaks inner loop
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      if i == 3 do\n"
            "        break\n"
            "      end\n"
            "      sum = sum + 1\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(3, Result).  %% i=0,1,2 then break at i=3

break_first_iteration_test() ->
    %% Break immediately
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 42\n"
            "    for i in 0..100 do\n"
            "      break\n"
            "    end\n"
            "    return x\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

%%% ===================================================================
%%% Continue (WP-010)
%%% ===================================================================

continue_skip_even_test() ->
    %% sum of odd numbers 0..10: 1+3+5+7+9 = 25
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      if i % 2 == 0 do\n"
            "        continue\n"
            "      end\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(25, Result).

continue_skip_first_test() ->
    %% Continue skips i=0, sums 1+2+3+4 = 10
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..5 do\n"
            "      if i == 0 do\n"
            "        continue\n"
            "      end\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(10, Result).

continue_all_iterations_test() ->
    %% Continue every iteration — body after continue never executes
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..5 do\n"
            "      continue\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(0, Result).

break_and_continue_combined_test() ->
    %% Skip even, break at 7 → sum = 1+3+5 = 9
    Src = <<"xdp test do\n"
            "  fn main(ctx) -> u64 do\n"
            "    let sum = 0\n"
            "    for i in 0..10 do\n"
            "      if i == 7 do\n"
            "        break\n"
            "      end\n"
            "      if i % 2 == 0 do\n"
            "        continue\n"
            "      end\n"
            "      sum = sum + i\n"
            "    end\n"
            "    return sum\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(9, Result).

%%% ===================================================================
%%% WP-012: Struct field access with correct offsets
%%% ===================================================================

struct_field_access_second_u32_test() ->
    %% Struct with two u32 fields: reading field2 should return its value (not field1)
    Src = <<"xdp test do\n"
            "  type Pair do\n"
            "    a: u32\n"
            "    b: u32\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let s = %Pair{a: 10, b: 42}\n"
            "    return s.b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(42, Result).

struct_field_access_first_u32_test() ->
    %% Reading the first field should return its value
    Src = <<"xdp test do\n"
            "  type Pair do\n"
            "    a: u32\n"
            "    b: u32\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let s = %Pair{a: 10, b: 42}\n"
            "    return s.a\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(10, Result).

struct_field_access_u64_test() ->
    %% Struct with u64 fields
    Src = <<"xdp test do\n"
            "  type Wide do\n"
            "    x: u64\n"
            "    y: u64\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let w = %Wide{x: 100, y: 200}\n"
            "    return w.y\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(200, Result).

struct_field_access_mixed_sizes_test() ->
    %% Struct with mixed u32 and u64 fields — tests alignment
    Src = <<"xdp test do\n"
            "  type Mixed do\n"
            "    a: u32\n"
            "    b: u64\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let m = %Mixed{a: 5, b: 999}\n"
            "    return m.b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(999, Result).

struct_field_access_three_fields_test() ->
    %% Three-field struct: verify each field is independently readable
    Src = <<"xdp test do\n"
            "  type Triple do\n"
            "    x: u32\n"
            "    y: u32\n"
            "    z: u32\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let t = %Triple{x: 1, y: 2, z: 3}\n"
            "    return t.y + t.z\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    {ok, Result} = ebpf_vm:run(Bin, #{}),
    ?assertEqual(5, Result).

struct_field_codegen_offset_test() ->
    %% Verify that struct field access generates correct offsets in bytecode
    Src = <<"xdp test do\n"
            "  type Pair do\n"
            "    a: u32\n"
            "    b: u32\n"
            "  end\n"
            "  fn main(ctx) -> u64 do\n"
            "    let s = %Pair{a: 10, b: 42}\n"
            "    return s.b\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% There should be an ldxw with offset 4 (second u32 field)
    ?assert(lists:any(fun({ldxw, _, _, 4, _}) -> true; (_) -> false end, Insns)).

%%% ===================================================================
%%% WP-009: Map Operations
%%% ===================================================================

%% map_update generates call 2 in bytecode
map_update_bytecode_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = 42\n"
            "    map_update(stats, key, val)\n"
            "    return 0\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% Must contain call with imm=2 (map_update_elem)
    ?assert(lists:any(fun({call, 0, 0, 0, 2}) -> true; (_) -> false end, Insns)).

%% map_lookup generates call 1 in bytecode
map_lookup_bytecode_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = map_lookup(stats, key)\n"
            "    return val\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% Must contain call with imm=1 (map_lookup_elem)
    ?assert(lists:any(fun({call, 0, 0, 0, 1}) -> true; (_) -> false end, Insns)).

%% map_delete generates call 3 in bytecode
map_delete_bytecode_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    map_delete(stats, key)\n"
            "    return 0\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% Must contain call with imm=3 (map_delete_elem)
    ?assert(lists:any(fun({call, 0, 0, 0, 3}) -> true; (_) -> false end, Insns)).

%% NULL check is present after map_lookup
map_lookup_null_check_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = map_lookup(stats, key)\n"
            "    return val\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% After call 1, there must be a conditional jump (jeq_reg or jeq_imm)
    %% checking for NULL (0). Find the call instruction index.
    CallIdx = find_insn_idx(Insns, fun({call, 0, 0, 0, 1}) -> true; (_) -> false end),
    ?assert(CallIdx =/= not_found),
    %% There should be a jeq (NULL check) somewhere after the call
    AfterCall = lists:nthtail(CallIdx, Insns),
    HasNullCheck = lists:any(fun
        ({jeq_imm, _, _, _, 0}) -> true;   %% jeq rX, 0, off
        ({jne_imm, _, _, _, 0}) -> true;   %% jne rX, 0, off
        ({jeq_reg, _, _, _, _}) -> true;    %% jeq rX, rY, off (comparing with zero reg)
        ({jne_reg, _, _, _, _}) -> true;
        (_) -> false
    end, AfterCall),
    ?assert(HasNullCheck).

%% ld_map_fd is present in map_lookup bytecode
map_lookup_ld_map_fd_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = map_lookup(stats, key)\n"
            "    return val\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src, #{peephole => false}),
    Insns = decode_all(Bin),
    %% Must contain ld_map_fd instruction
    ?assert(lists:any(fun({ld_map_fd, _, _, _, _}) -> true; (_) -> false end, Insns)).

%% End-to-end: map_update + map_lookup via VM
map_update_lookup_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = 42\n"
            "    map_update(stats, key, val)\n"
            "    let result = map_lookup(stats, key)\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    %% Run with a map: stats is map index 0
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(42, Result).

%% End-to-end: map_lookup on non-existent key returns 0 (NULL)
map_lookup_null_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 99\n"
            "    let result = map_lookup(stats, key)\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(0, Result).

%% End-to-end: map_update + map_delete + map_lookup returns 0
map_delete_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    let val = 42\n"
            "    map_update(stats, key, val)\n"
            "    map_delete(stats, key)\n"
            "    let result = map_lookup(stats, key)\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(0, Result).

%% End-to-end: method-call syntax stats.lookup(key)
map_method_syntax_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 5\n"
            "    let val = 100\n"
            "    stats.update(key, val)\n"
            "    let result = stats.lookup(key)\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(100, Result).

%% End-to-end: multiple map updates with different keys
map_multiple_keys_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let k1 = 1\n"
            "    let k2 = 2\n"
            "    map_update(stats, k1, 10)\n"
            "    map_update(stats, k2, 20)\n"
            "    let v1 = map_lookup(stats, k1)\n"
            "    let v2 = map_lookup(stats, k2)\n"
            "    return v1 + v2\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(30, Result).

%% End-to-end: map_update overwrites existing value
map_overwrite_e2e_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
            "  fn main(ctx) -> u64 do\n"
            "    let key = 1\n"
            "    map_update(stats, key, 10)\n"
            "    map_update(stats, key, 42)\n"
            "    let result = map_lookup(stats, key)\n"
            "    return result\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 1024}]}),
    ?assertEqual(42, Result).

%% Regression: variable read AFTER 2 consecutive helper calls.
%% The variable must survive both calls (spill + correct reload).
%% Bug fixed 2026-03-13: codegen did not reload spilled operands in
%% cond_br terminators, and regalloc used point clobber intervals.
spill_after_two_helpers_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 256\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 50\n"
            "    let count = map_lookup(stats, x)\n"
            "    map_update(stats, x, count + 1)\n"
            "    if x > 10 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 256}]}),
    %% x=50 > 10, so must return 1
    ?assertEqual(1, Result).

%% Same pattern but condition is false: x=5 <= 10 → return 0
spill_after_two_helpers_false_test() ->
    Src = <<"xdp test do\n"
            "  map :stats, hash, key: u32, value: u64, max_entries: 256\n"
            "  fn main(ctx) -> u64 do\n"
            "    let x = 5\n"
            "    let count = map_lookup(stats, x)\n"
            "    map_update(stats, x, count + 1)\n"
            "    if x > 10 do\n"
            "      return 1\n"
            "    else\n"
            "      return 0\n"
            "    end\n"
            "  end\n"
            "end">>,
    {ok, Bin} = ebl_compile:compile(Src),
    {ok, Result} = ebpf_vm:run(Bin, #{}, #{maps => [{hash, 4, 8, 256}]}),
    ?assertEqual(0, Result).

%% Helper: find index of first instruction matching predicate
find_insn_idx(Insns, Pred) ->
    find_insn_idx(Insns, Pred, 0).
find_insn_idx([], _Pred, _Idx) -> not_found;
find_insn_idx([I | Rest], Pred, Idx) ->
    case Pred(I) of
        true -> Idx;
        false -> find_insn_idx(Rest, Pred, Idx + 1)
    end.
