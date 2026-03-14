-module(ebl_pre_verify_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Positive tests — must return ok (hand-crafted bytecode)
%%% ===================================================================

simple_mov_exit_test() ->
    %% mov r0, 42; exit
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

xdp_pass_test() ->
    %% mov r0, 2; exit  (XDP_PASS)
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 2),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

map_lookup_with_null_check_test() ->
    %% Simulate: call 1 (map_lookup); jeq r0, 0, +1; ldxdw r1, [r0+0]; exit
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),      %% 0: dummy (not real map_lookup setup)
        ebpf_insn:mov64_imm(1, 0),       %% 1: r1 = map ptr (setup)
        ebpf_insn:mov64_imm(2, 0),       %% 2: r2 = key ptr (setup)
        ebpf_insn:call(1),               %% 3: call map_lookup_elem
        ebpf_insn:jeq_imm(0, 0, 2),     %% 4: if r0 == 0 goto +2 (skip load, go to exit)
        ebpf_insn:ldxdw(1, 0, 0),       %% 5: r1 = [r0+0] (safe, null checked)
        ebpf_insn:mov64_imm(0, 0),       %% 6: r0 = 0
        ebpf_insn:exit_insn()            %% 7: exit
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

%%% ===================================================================
%%% Negative tests — must detect errors
%%% ===================================================================

uninitialized_register_test() ->
    %% Read R5 without writing it first (add64_reg r0, r5)
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:add64_reg(0, 5),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({uninitialized_register, 5, _}) -> true; (_) -> false end, Errors)).

stack_overflow_test() ->
    %% stxdw [r10-520], r1  — offset -520 exceeds stack limit 512
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, -520, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({stack_overflow, -520, 512}) -> true; (_) -> false end, Errors)).

no_exit_test() ->
    %% Program without exit instruction
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42)
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:member({no_exit_instruction}, Errors)).

invalid_jump_target_test() ->
    %% ja +100 in a 3-instruction program
    Bin = iolist_to_binary([
        ebpf_insn:ja(100),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({invalid_jump_target, _, _}) -> true; (_) -> false end, Errors)).

division_by_zero_test() ->
    %% div64_imm r0, 0
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:div64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({division_by_zero_imm, _}) -> true; (_) -> false end, Errors)).

null_deref_test() ->
    %% call 1 (map_lookup); ldxdw r1, [r0+0]  — no null check!
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:mov64_imm(1, 0),
        ebpf_insn:mov64_imm(2, 0),
        ebpf_insn:call(1),              %% r0 = maybe_null
        ebpf_insn:ldxdw(1, 0, 0),       %% deref r0 without null check!
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({possible_null_deref, 0, _}) -> true; (_) -> false end, Errors)).

instruction_limit_test() ->
    %% Use a low limit
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin, #{insn_limit => 100})),
    {error, Errors} = ebl_pre_verify:check(Bin, #{insn_limit => 1}),
    ?assert(lists:any(fun({instruction_limit_exceeded, _, _}) -> true; (_) -> false end, Errors)).

%%% ===================================================================
%%% Extended negative tests — edge cases
%%% ===================================================================

multiple_errors_test() ->
    %% Program with multiple issues: no exit, div by zero, uninitialized reg
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:div64_imm(0, 0),       %% div by zero
        ebpf_insn:add64_reg(0, 5)         %% uninit R5; also no exit
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({no_exit_instruction}) -> true; (_) -> false end, Errors)),
    ?assert(lists:any(fun({division_by_zero_imm, _}) -> true; (_) -> false end, Errors)),
    ?assert(lists:any(fun({uninitialized_register, 5, _}) -> true; (_) -> false end, Errors)).

jump_to_position_zero_test() ->
    %% ja with offset -1 from PC=0 would be target = 0+1+(-1) = 0 → valid self-loop
    %% But from PC=1 to target 0 is a backwards jump which is valid
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),      %% PC 0
        ebpf_insn:ja(-2),               %% PC 1: target = 1+1+(-2) = 0 → valid
        ebpf_insn:exit_insn()            %% PC 2
    ]),
    %% Jump to PC 0 is valid (within bounds, not LD64 second slot)
    Result = ebl_pre_verify:check(Bin),
    case Result of
        ok -> ok;
        {error, Errors} ->
            %% Should NOT have invalid_jump_target for target 0
            ?assertNot(lists:any(
                fun({invalid_jump_target, 0, _}) -> true; (_) -> false end,
                Errors))
    end.

backwards_jump_test() ->
    %% Backward jump creating a loop: valid as long as target is in bounds
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),      %% PC 0
        ebpf_insn:mov64_imm(2, 5),       %% PC 1: loop counter
        ebpf_insn:add64_imm(0, 1),       %% PC 2: r0 += 1
        ebpf_insn:sub64_imm(2, 1),       %% PC 3: r2 -= 1
        ebpf_insn:jgt_imm(2, 0, -3),    %% PC 4: if r2 > 0 goto PC 2 (off = -3)
        ebpf_insn:exit_insn()            %% PC 5
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

write_r10_test() ->
    %% R10 is the read-only frame pointer; writing to it via mov is disallowed
    %% by the kernel verifier.  Our pre-verifier tracks abstract state but
    %% does not specifically block R10 writes — the kernel verifier catches that.
    %% Here we verify the pre-verifier at least doesn't crash on it.
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(10, 0),     %% Write to R10 (illegal in real BPF)
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    %% Pre-verifier processes this without crashing
    _Result = ebl_pre_verify:check(Bin),
    ok.

positive_stack_offset_test() ->
    %% Stack access with offset >= 0 is invalid
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, 0, 1),      %% [r10+0] — offset 0 is invalid
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({invalid_stack_access, 0, _}) -> true; (_) -> false end, Errors)).

mod_by_zero_test() ->
    %% mod64_imm r0, 0 — division by zero variant
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:mod64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({division_by_zero_imm, _}) -> true; (_) -> false end, Errors)).

div32_by_zero_test() ->
    %% div32_imm r0, 0
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:div32_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({division_by_zero_imm, _}) -> true; (_) -> false end, Errors)).

mod32_by_zero_test() ->
    %% mod32_imm r0, 0
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 42),
        ebpf_insn:mod32_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({division_by_zero_imm, _}) -> true; (_) -> false end, Errors)).

jump_past_end_test() ->
    %% Conditional jump past the end of the program
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:jeq_imm(0, 1, 50),   %% target way out of bounds
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({invalid_jump_target, _, _}) -> true; (_) -> false end, Errors)).

negative_jump_out_of_bounds_test() ->
    %% Jump to negative PC
    Bin = iolist_to_binary([
        ebpf_insn:ja(-10),              %% target = 0+1+(-10) = -9 → out of bounds
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({invalid_jump_target, _, _}) -> true; (_) -> false end, Errors)).

exit_without_r0_init_test() ->
    %% Just an exit — R0 not initialized
    Bin = iolist_to_binary([
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({uninitialized_register, 0, _}) -> true; (_) -> false end, Errors)).

call_clobbers_r1_r5_test() ->
    %% After a call, R1-R5 are clobbered — reading them should fail
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(1, 0),      %% init R1
        ebpf_insn:mov64_imm(2, 0),      %% init R2
        ebpf_insn:call(5),              %% call ktime_get_ns; clobbers R1-R5
        ebpf_insn:add64_reg(0, 1),      %% read R1 — not initialized after call!
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({uninitialized_register, 1, _}) -> true; (_) -> false end, Errors)).

%%% ===================================================================
%%% P9: R10 Write Protection
%%% ===================================================================

r10_write_mov_imm_test() ->
    %% mov64_imm(10, 0) writes to R10 — must be rejected
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(10, 0),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({r10_write, 0}) -> true; (_) -> false end, Errors)).

r10_write_mov_reg_test() ->
    %% mov64_reg(10, 1) writes to R10 — must be rejected
    Bin = iolist_to_binary([
        ebpf_insn:mov64_reg(10, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({r10_write, 0}) -> true; (_) -> false end, Errors)).

r10_write_alu_test() ->
    %% add64_imm(10, 8) modifies R10 — must be rejected
    Bin = iolist_to_binary([
        ebpf_insn:add64_imm(10, 8),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({r10_write, 0}) -> true; (_) -> false end, Errors)).

r10_read_stack_ok_test() ->
    %% Writing TO stack via R10 and reading FROM stack via R10 is fine —
    %% neither modifies R10 itself.
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:ldxdw(0, 10, -8),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

%%% ===================================================================
%%% P10: Stack Alignment
%%% ===================================================================

stack_align_dw_ok_test() ->
    %% stxdw at offset -8 — 8-byte aligned, should be ok
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, -8, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

stack_align_dw_bad_test() ->
    %% stxdw at offset -12 — not 8-byte aligned
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, -12, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({stack_misalign, -12, 8, 0}) -> true; (_) -> false end, Errors)).

stack_align_w_ok_test() ->
    %% stxw at offset -4 — 4-byte aligned, should be ok
    Bin = iolist_to_binary([
        ebpf_insn:stxw(10, -4, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

stack_align_w_bad_test() ->
    %% stxw at offset -3 — not 4-byte aligned
    Bin = iolist_to_binary([
        ebpf_insn:stxw(10, -3, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({stack_misalign, -3, 4, 0}) -> true; (_) -> false end, Errors)).

stack_align_byte_ok_test() ->
    %% stxb at offset -1 — no alignment requirement for bytes
    Bin = iolist_to_binary([
        ebpf_insn:stxb(10, -1, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

stack_align_h_ok_test() ->
    %% stxh at offset -2 — 2-byte aligned, should be ok
    Bin = iolist_to_binary([
        ebpf_insn:stxh(10, -2, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

stack_align_h_bad_test() ->
    %% stxh at offset -3 — not 2-byte aligned
    Bin = iolist_to_binary([
        ebpf_insn:stxh(10, -3, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({stack_misalign, -3, 2, 0}) -> true; (_) -> false end, Errors)).

stack_align_dw_16_ok_test() ->
    %% stxdw at offset -16 — 8-byte aligned, should be ok
    Bin = iolist_to_binary([
        ebpf_insn:stxdw(10, -16, 1),
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(ok, ebl_pre_verify:check(Bin)).

%%% ===================================================================
%%% P11: Unreachable Code Detection
%%% ===================================================================

unreachable_after_jump_test() ->
    %% PC 2 is unreachable because PC 1 jumps unconditionally to PC 3
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),      %% PC 0
        ebpf_insn:ja(1),                 %% PC 1: jump to PC 3
        ebpf_insn:mov64_imm(0, 42),      %% PC 2: UNREACHABLE
        ebpf_insn:exit_insn()            %% PC 3: exit
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({unreachable_code, 2}) -> true; (_) -> false end, Errors)).

all_reachable_conditional_test() ->
    %% All instructions reachable via conditional branch
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 1),      %% PC 0
        ebpf_insn:jeq_imm(0, 0, 1),     %% PC 1: if r0==0 goto PC 3
        ebpf_insn:mov64_imm(0, 2),      %% PC 2: reached via fall-through
        ebpf_insn:exit_insn()            %% PC 3: reached via both paths
    ]),
    Result = ebl_pre_verify:check(Bin),
    case Result of
        ok -> ok;
        {error, Errors} ->
            ?assertNot(lists:any(
                fun({unreachable_code, _}) -> true; (_) -> false end,
                Errors))
    end.

linear_no_unreachable_test() ->
    %% Linear program — dead code after exit should NOT trigger unreachable
    %% check (linear program exemption: no jumps in program)
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn(),
        ebpf_insn:mov64_imm(0, 1),      %% Dead code but no jump in program
        ebpf_insn:exit_insn()
    ]),
    Result = ebl_pre_verify:check(Bin),
    case Result of
        ok -> ok;
        {error, Errors} ->
            ?assertNot(lists:any(
                fun({unreachable_code, _}) -> true; (_) -> false end,
                Errors))
    end.

%%% ===================================================================
%%% P12: Helper Argument Type Checking
%%% ===================================================================

helper_arg_map_lookup_scalar_r1_test() ->
    %% R1 is a scalar (not ptr_to_map), calling map_lookup_elem
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:mov64_imm(1, 42),     %% R1 = scalar (should be ptr_to_map)
        ebpf_insn:mov64_imm(2, 0),      %% R2 = scalar (should be ptr_to_stack)
        ebpf_insn:call(1),              %% map_lookup_elem
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    {error, Errors} = ebl_pre_verify:check(Bin),
    ?assert(lists:any(fun({invalid_helper_arg, 1, 1, ptr_to_map, _, _}) -> true;
                         (_) -> false end, Errors)).

helper_non_map_no_typecheck_test() ->
    %% Non-map helper (call 5 = ktime_get_ns) should not require typed args
    Bin = iolist_to_binary([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:call(5),              %% ktime_get_ns — no arg type requirements
        ebpf_insn:exit_insn()
    ]),
    Result = ebl_pre_verify:check(Bin),
    case Result of
        ok -> ok;
        {error, Errors} ->
            ?assertNot(lists:any(
                fun({invalid_helper_arg, _, _, _, _, _}) -> true; (_) -> false end,
                Errors))
    end.

%%% ===================================================================
%%% Compiler output acceptance tests — MOST IMPORTANT
%%% Every program the compiler produces MUST pass the pre-verifier.
%%% ===================================================================

compiler_output_acceptance_test_() ->
    Programs = [
        %% Basic returns
        {"pass",
         <<"xdp test do\n  fn main(ctx) -> action do\n    return :pass\n  end\nend">>},
        {"drop",
         <<"xdp test do\n  fn main(ctx) -> action do\n    return :drop\n  end\nend">>},
        {"literal_42",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return 42\n  end\nend">>},
        {"literal_0",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return 0\n  end\nend">>},

        %% Arithmetic
        {"add",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10 + 32\n    return x\n  end\nend">>},
        {"sub",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 50 - 8\n    return x\n  end\nend">>},
        {"mul",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 6 * 7\n    return x\n  end\nend">>},
        {"div",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 84 / 2\n    return x\n  end\nend">>},
        {"mod",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10 % 3\n    return x\n  end\nend">>},
        {"complex_arith",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let a = 1\n    let b = 2\n    let c = 3\n    return a + b * c\n  end\nend">>},

        %% Comparison + if/else
        {"eq_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 == 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},
        {"gt_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 > 3 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},
        {"lt_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 3 < 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},
        {"ne_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 != 3 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},
        {"ge_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 >= 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},
        {"le_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 <= 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>},

        %% Control flow
        {"if_else",
         <<"xdp test do\n  fn main(ctx) -> action do\n    if 1 > 0 do\n      return :pass\n    else\n      return :drop\n    end\n  end\nend">>},
        {"nested_if",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 1 > 0 do\n      if 2 > 1 do\n        return 1\n      else\n        return 2\n      end\n    else\n      return 3\n    end\n  end\nend">>},
        {"elif",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 5\n    if x > 10 do\n      return 3\n    elif x > 3 do\n      return 2\n    else\n      return 1\n    end\n  end\nend">>},
        {"if_no_return",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 5\n    if true do\n      x = 42\n    end\n    return x\n  end\nend">>},

        %% Loops
        {"for_loop",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..5 do\n      s = s + i\n    end\n    return s\n  end\nend">>},
        {"for_zero_iterations",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..0 do\n      s = s + i\n    end\n    return s\n  end\nend">>},
        {"break",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..10 do\n      if i == 5 do\n        break\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>},
        {"continue",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..5 do\n      if i == 2 do\n        continue\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>},

        %% Context access
        {"ctx_data",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return ctx.data\n  end\nend">>},
        {"ctx_data_end",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return ctx.data_end\n  end\nend">>},
        {"ctx_ifindex",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return ctx.ingress_ifindex\n  end\nend">>},
        {"ctx_data_meta",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    return ctx.data_meta\n  end\nend">>},
        {"ctx_in_condition",
         <<"xdp test do\n  fn main(ctx) -> action do\n    if ctx.ingress_ifindex == 1 do\n      return :drop\n    end\n    return :pass\n  end\nend">>},

        %% Multiple variables (register pressure)
        {"many_vars",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let a = 1\n    let b = 2\n    let c = 3\n    let d = 4\n    let e = 5\n    return a + b + c + d + e\n  end\nend">>},

        %% Variable reassignment
        {"reassign",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 1\n    x = 42\n    return x\n  end\nend">>},

        %% Multiple let + complex expression
        {"multi_stmt",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10\n    let y = 20\n    let z = x + y\n    return z\n  end\nend">>},

        %% TC program type
        {"tc_program",
         <<"tc test do\n  fn main(ctx) -> action do\n    return :ok\n  end\nend">>},

        %% Boolean literals
        {"bool_true",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if true do\n      return 1\n    end\n    return 0\n  end\nend">>},
        {"bool_false",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    if false do\n      return 1\n    end\n    return 0\n  end\nend">>},

        %% Break and continue combined
        {"break_continue",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..10 do\n      if i == 7 do\n        break\n      end\n      if i % 2 == 0 do\n        continue\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>},

        %% Nested loops
        {"nested_loop",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..3 do\n      for j in 0..3 do\n        s = s + 1\n      end\n    end\n    return s\n  end\nend">>},

        %% Ctx arithmetic
        {"ctx_arith",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let d = ctx.data\n    let e = ctx.data_end\n    return e - d\n  end\nend">>},

        %% Heavy register pressure (forces spills)
        {"register_pressure",
         <<"xdp test do\n  fn main(ctx) -> u64 do\n    let a = 1\n    let b = 2\n    let c = 3\n    let d = 4\n    let e = 5\n    let f = 6\n    let g = 7\n    let h = 8\n    return a + b + c + d + e + f + g + h\n  end\nend">>}
    ],
    [{Name, fun() ->
        {ok, Bytecode} = ebl_compile:compile(Src),
        ?assertEqual(ok, ebl_pre_verify:check(Bytecode),
                     "Pre-verifier rejected compiler output: " ++ Name)
    end} || {Name, Src} <- Programs].
