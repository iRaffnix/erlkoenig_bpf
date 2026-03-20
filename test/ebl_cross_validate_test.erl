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

%% @doc Cross-validation tests: run programs in BOTH the Erlang VM and uBPF,
%% then compare results to ensure both VMs agree.
%%
%% Only tests programs that do NOT access context fields (ctx.data etc.)
%% because the Erlang VM uses virtual addresses (CTX_BASE=0x10000000,
%% PKT_BASE=0x20000000) while uBPF gets raw buffer pointers.
-module(ebl_cross_validate_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Check if the ubpf_port binary is available.
port_available() ->
    try
        PortPath = filename:join(code:priv_dir(erlkoenig_ebpf), "ubpf_port"),
        filelib:is_file(PortPath)
    catch
        _:_ -> false
    end.

%% Helper: run a cross-validation test with a fresh port, skip if unavailable.
with_port(TestFun) ->
    case port_available() of
        false ->
            {skip, "ubpf_port not available"};
        true ->
            fun() ->
                {ok, Port} = ebpf_ubpf:start(),
                try
                    TestFun(Port)
                after
                    catch ebpf_ubpf:stop(Port)
                end
            end
    end.

%% Run program in both VMs and assert identical results.
cross_validate(Port, Source, Expected) ->
    {ok, Bytecode} = ebl_compile:compile(Source),

    %% 1. Erlang VM — dummy context (24 bytes = 192 bits, all zeros)
    DummyCtx = #{ctx => <<0:192>>, packet => <<>>},
    ErlResult = ebpf_vm:run(Bytecode, DummyCtx),

    %% 2. uBPF — same dummy context as raw binary
    ok = ebpf_ubpf:load(Port, Bytecode),
    UbpfResult = ebpf_ubpf:run(Port, <<0:192>>),

    %% 3. Both must succeed
    ?assertMatch({ok, _}, ErlResult),
    ?assertMatch({ok, _}, UbpfResult),

    {ok, ErlVal} = ErlResult,
    {ok, UbpfVal} = UbpfResult,

    %% 4. Results must match each other AND the expected value
    ?assertEqual(
        Expected,
        ErlVal,
        "Erlang VM returned unexpected value"
    ),
    ?assertEqual(
        Expected,
        UbpfVal,
        "uBPF returned unexpected value"
    ),
    ?assertEqual(
        ErlVal,
        UbpfVal,
        "Erlang VM and uBPF disagree"
    ).

%%% ===================================================================
%%% Test programs — only those safe for cross-validation
%%% (no ctx field access, no maps, no time-dependent helpers)
%%% ===================================================================

test_programs() ->
    [
        %% --- Basic returns ---
        {"cv_pass", <<"xdp test do\n  fn main(ctx) -> action do\n    return :pass\n  end\nend">>,
            2},
        {"cv_drop", <<"xdp test do\n  fn main(ctx) -> action do\n    return :drop\n  end\nend">>,
            1},
        {"cv_literal_42", <<"xdp test do\n  fn main(ctx) -> u64 do\n    return 42\n  end\nend">>,
            42},
        {"cv_literal_0", <<"xdp test do\n  fn main(ctx) -> u64 do\n    return 0\n  end\nend">>, 0},

        %% --- Arithmetic ---
        {"cv_add",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10 + 32\n    return x\n  end\nend">>,
            42},
        {"cv_sub",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 50 - 8\n    return x\n  end\nend">>,
            42},
        {"cv_mul",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 6 * 7\n    return x\n  end\nend">>,
            42},
        {"cv_div",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 84 / 2\n    return x\n  end\nend">>,
            42},
        {"cv_mod",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10 % 3\n    return x\n  end\nend">>,
            1},
        {"cv_complex_arith",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let a = 1\n    let b = 2\n    let c = 3\n    return a + b * c\n  end\nend">>,
            7},

        %% --- Comparisons ---
        {"cv_gt_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 > 3 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},
        {"cv_gt_false",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 3 > 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            0},
        {"cv_eq_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 == 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},
        {"cv_ne_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 != 3 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},
        {"cv_lt_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 3 < 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},
        {"cv_ge_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 >= 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},
        {"cv_le_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 5 <= 5 do\n      return 1\n    else\n      return 0\n    end\n  end\nend">>,
            1},

        %% --- Control flow ---
        {"cv_elif",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 5\n    if x > 10 do\n      return 3\n    elif x > 3 do\n      return 2\n    else\n      return 1\n    end\n  end\nend">>,
            2},
        {"cv_nested_if",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if 1 > 0 do\n      if 2 > 1 do\n        return 1\n      else\n        return 2\n      end\n    else\n      return 3\n    end\n  end\nend">>,
            1},
        {"cv_bool_true",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if true do\n      return 1\n    end\n    return 0\n  end\nend">>,
            1},
        {"cv_bool_false",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    if false do\n      return 1\n    end\n    return 0\n  end\nend">>,
            0},

        %% --- Variable ops ---
        {"cv_reassign",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 1\n    x = 42\n    return x\n  end\nend">>,
            42},
        {"cv_multi_vars",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let a = 1\n    let b = 2\n    let c = 3\n    let d = 4\n    let e = 5\n    return a + b + c + d + e\n  end\nend">>,
            15},
        {"cv_multi_stmt",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let x = 10\n    let y = 20\n    let z = x + y\n    return z\n  end\nend">>,
            30},

        %% --- Loops ---
        {"cv_for_sum",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..5 do\n      s = s + i\n    end\n    return s\n  end\nend">>,
            10},
        {"cv_for_zero_iter",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..0 do\n      s = s + i\n    end\n    return s\n  end\nend">>,
            0},
        {"cv_for_break",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..10 do\n      if i == 5 do\n        break\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>,
            10},
        {"cv_for_continue",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..5 do\n      if i == 2 do\n        continue\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>,
            8},
        {"cv_break_continue",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..10 do\n      if i == 7 do\n        break\n      end\n      if i % 2 == 0 do\n        continue\n      end\n      s = s + i\n    end\n    return s\n  end\nend">>,
            9},
        {"cv_nested_loop",
            <<"xdp test do\n  fn main(ctx) -> u64 do\n    let s = 0\n    for i in 0..3 do\n      for j in 0..3 do\n        s = s + 1\n      end\n    end\n    return s\n  end\nend">>,
            9}
    ].

%%% ===================================================================
%%% Test generator
%%% ===================================================================

cross_validate_test_() ->
    [
        {
            "cross_validate: " ++ Name,
            with_port(fun(Port) -> cross_validate(Port, Src, Expected) end)
        }
     || {Name, Src, Expected} <- test_programs()
    ] ++
        [
            {
                "cross_validate_maps: " ++ Name,
                with_port(fun(Port) -> cross_validate_with_maps(Port, Src, Maps, Expected) end)
            }
         || {Name, Src, Maps, Expected} <- test_programs_with_maps()
        ].

%% Run program in both VMs with map support and assert identical results.
cross_validate_with_maps(Port, Source, Maps, Expected) ->
    {ok, Bytecode} = ebl_compile:compile(Source),

    %% 1. Erlang VM
    DummyCtx = #{ctx => <<0:192>>, packet => <<>>},
    ErlResult = ebpf_vm:run(Bytecode, DummyCtx, #{maps => Maps}),

    %% 2. uBPF — create maps and load
    ebpf_ubpf:reset_maps(Port),
    lists:foreach(
        fun({_Type, KS, VS, MaxE}) ->
            {ok, _Fd} = ebpf_ubpf:create_map(Port, KS, VS, MaxE)
        end,
        Maps
    ),
    ok = ebpf_ubpf:load(Port, Bytecode),
    UbpfResult = ebpf_ubpf:run(Port, <<0:192>>),

    %% 3. Both must succeed
    ?assertMatch({ok, _}, ErlResult),
    ?assertMatch({ok, _}, UbpfResult),

    {ok, ErlVal} = ErlResult,
    {ok, UbpfVal} = UbpfResult,

    %% 4. Results must match each other AND the expected value
    ?assertEqual(Expected, ErlVal, "Erlang VM returned unexpected value"),
    ?assertEqual(Expected, UbpfVal, "uBPF returned unexpected value"),
    ?assertEqual(ErlVal, UbpfVal, "Erlang VM and uBPF disagree").

%%% ===================================================================
%%% Map test programs — cross-validated with maps
%%% ===================================================================

test_programs_with_maps() ->
    [
        %% Variable read after 2 consecutive helper calls (spill regression)
        {"spill_after_two_helpers_true",
            <<
                "xdp test do\n"
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
                "end"
            >>,
            [{hash, 4, 8, 256}], 1},

        {"spill_after_two_helpers_false",
            <<
                "xdp test do\n"
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
                "end"
            >>,
            [{hash, 4, 8, 256}], 0},

        %% map_update + map_lookup round-trip
        {"map_update_lookup",
            <<
                "xdp test do\n"
                "  map :stats, hash, key: u32, value: u64, max_entries: 1024\n"
                "  fn main(ctx) -> u64 do\n"
                "    let key = 1\n"
                "    map_update(stats, key, 42)\n"
                "    let result = map_lookup(stats, key)\n"
                "    return result\n"
                "  end\n"
                "end"
            >>,
            [{hash, 4, 8, 1024}], 42},

        %% Three consecutive helpers: update, lookup, use result in condition
        {"three_helpers_condition",
            <<
                "xdp test do\n"
                "  map :m, hash, key: u32, value: u64, max_entries: 64\n"
                "  fn main(ctx) -> u64 do\n"
                "    let k = 7\n"
                "    map_update(m, k, 100)\n"
                "    let v = map_lookup(m, k)\n"
                "    map_update(m, k, v + 1)\n"
                "    if k == 7 do\n"
                "      return v\n"
                "    else\n"
                "      return 0\n"
                "    end\n"
                "  end\n"
                "end"
            >>,
            [{hash, 4, 8, 64}], 100}
    ].
