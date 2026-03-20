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

-module(ebl_integration_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%% ===================================================================
%%% WP-019: Integration Test Suite
%%%
%%% Tests realistic BPF programs through the full pipeline:
%%%   compile -> pre-verify -> VM run -> result check
%%% ===================================================================

%%% -------------------------------------------------------------------
%%% Helper: run a program through compile -> verify -> VM
%%% -------------------------------------------------------------------

run_pipeline(Source, Ctx, Expected) ->
    %% 1. Compile
    {ok, Bytecode} = ebl_compile:compile(Source),
    %% 2. Pre-verify
    ?assertEqual(ok, ebl_pre_verify:check(Bytecode)),
    %% 3. VM run
    {ok, Result} = ebpf_vm:run(Bytecode, Ctx),
    %% 4. Check result
    ?assertEqual(Expected, Result).

%%% ===================================================================
%%% P1: Simple XDP Drop/Pass
%%% ===================================================================

p1_xdp_drop_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> action do\n"
        "    return :drop\n"
        "  end\n"
        "end"
    >>,
    %% XDP_DROP = 1
    run_pipeline(Src, #{packet => Pkt}, 1).

p1_xdp_pass_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> action do\n"
        "    return :pass\n"
        "  end\n"
        "end"
    >>,
    %% XDP_PASS = 2
    run_pipeline(Src, #{packet => Pkt}, 2).

%%% ===================================================================
%%% P2: Arithmetic + Variables
%%% ===================================================================

p2_arithmetic_variables_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let x = 10\n"
        "    let y = 20\n"
        "    let z = x + y * 2\n"
        "    return z\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{}, 50).

%%% ===================================================================
%%% P3: Comparison Chain (Elif)
%%% ===================================================================

p3_elif_chain_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let x = 7\n"
        "    if x > 10 do\n"
        "      return 3\n"
        "    elif x > 5 do\n"
        "      return 2\n"
        "    elif x > 0 do\n"
        "      return 1\n"
        "    else\n"
        "      return 0\n"
        "    end\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{}, 2).

%%% ===================================================================
%%% P4: For-Loop with Break
%%% ===================================================================

p4_for_loop_break_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let sum = 0\n"
        "    for i in 0..100 do\n"
        "      if i == 10 do\n"
        "        break\n"
        "      end\n"
        "      sum = sum + i\n"
        "    end\n"
        "    return sum\n"
        "  end\n"
        "end"
    >>,
    %% 0+1+2+...+9
    run_pipeline(Src, #{}, 45).

%%% ===================================================================
%%% P5: For-Loop with Continue
%%% ===================================================================

p5_for_loop_continue_test() ->
    Src = <<
        "xdp test do\n"
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
        "end"
    >>,
    %% 1+3+5+7+9
    run_pipeline(Src, #{}, 25).

%%% ===================================================================
%%% P6: Context Field Access (XDP)
%%% ===================================================================

p6_ctx_ingress_ifindex_test() ->
    %% XDP context layout: data(4) data_end(4) data_meta(4) ingress_ifindex(4) ...
    %% ingress_ifindex is at offset 12
    CtxBin = <<0:32, 0:32, 0:32, 42:32/little, 0:32, 0:32>>,
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    return ctx.ingress_ifindex\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{ctx => CtxBin}, 42).

%%% ===================================================================
%%% P7: Context Comparison
%%% ===================================================================

p7_ctx_comparison_pass_test() ->
    %% ifindex=1 -> PASS (2)
    CtxBin = <<0:32, 0:32, 0:32, 1:32/little, 0:32, 0:32>>,
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> action do\n"
        "    let ifindex = ctx.ingress_ifindex\n"
        "    if ifindex == 1 do\n"
        "      return :pass\n"
        "    else\n"
        "      return :drop\n"
        "    end\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{ctx => CtxBin}, 2).

p7_ctx_comparison_drop_test() ->
    %% ifindex=2 -> DROP (1)
    CtxBin = <<0:32, 0:32, 0:32, 2:32/little, 0:32, 0:32>>,
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> action do\n"
        "    let ifindex = ctx.ingress_ifindex\n"
        "    if ifindex == 1 do\n"
        "      return :pass\n"
        "    else\n"
        "      return :drop\n"
        "    end\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{ctx => CtxBin}, 1).

%%% ===================================================================
%%% P8: Helper Call (ktime_get_ns)
%%%
%%% ktime_get_ns is not yet exposed at the EBL source level, so this
%%% test assembles bytecode directly and runs verify + VM.
%%% ===================================================================

p8_helper_ktime_test() ->
    %% Bytecode equivalent of:
    %%   t = ktime_get_ns()
    %%   if t > 0: return PASS (2)
    %%   return DROP (1)
    Bytecode = ebpf_insn:assemble([
        %% R0 = ktime_get_ns()
        ebpf_insn:call(5),
        %% if R0 > 0 goto +1
        ebpf_insn:jgt_imm(0, 0, 1),
        %% R0 = 1 (DROP)
        ebpf_insn:mov64_imm(0, 1),
        %% R0 = 2 (PASS) — jump target
        ebpf_insn:mov64_imm(0, 2),
        ebpf_insn:exit_insn()
    ]),
    %% Pre-verify
    ?assertEqual(ok, ebl_pre_verify:check(Bytecode)),
    %% VM run
    {ok, Result} = ebpf_vm:run(Bytecode, #{}),
    %% ktime > 0 always
    ?assertEqual(2, Result).

%%% ===================================================================
%%% P9: Many Variables (Register Pressure)
%%% ===================================================================

p9_many_variables_test() ->
    Src = <<
        "xdp test do\n"
        "  fn main(ctx) -> u64 do\n"
        "    let a = 1\n"
        "    let b = 2\n"
        "    let c = 3\n"
        "    let d = 4\n"
        "    let e = 5\n"
        "    let f = 6\n"
        "    let g = 7\n"
        "    return a + b + c + d + e + f + g\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{}, 28).

%%% ===================================================================
%%% P10: Struct Access
%%% ===================================================================

p10_struct_access_test() ->
    Src = <<
        "xdp test do\n"
        "  type Point do\n"
        "    x: u32\n"
        "    y: u32\n"
        "  end\n"
        "  fn main(ctx) -> u64 do\n"
        "    let p = %Point{x: 10, y: 20}\n"
        "    return p.x + p.y\n"
        "  end\n"
        "end"
    >>,
    run_pipeline(Src, #{}, 30).
