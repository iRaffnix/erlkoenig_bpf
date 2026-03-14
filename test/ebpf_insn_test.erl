-module(ebpf_insn_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% WP-001 Acceptance Criterion:
%%% ebpf_insn:decode(ebpf_insn:mov64_imm(1, 42)) = {mov64_imm, 1, 0, 0, 42}
%%% ===================================================================

acceptance_test() ->
    ?assertEqual({mov64_imm, 1, 0, 0, 42},
                 ebpf_insn:decode(ebpf_insn:mov64_imm(1, 42))).

%%% ===================================================================
%%% Instruction size
%%% ===================================================================

insn_size_8_test() ->
    ?assertEqual(8, byte_size(ebpf_insn:mov64_imm(1, 42))).

insn_size_16_test() ->
    ?assertEqual(16, byte_size(ebpf_insn:ld64_imm(1, 16#DEADBEEF))).

ld_map_fd_size_test() ->
    ?assertEqual(16, byte_size(ebpf_insn:ld_map_fd(1, 5))).

%%% ===================================================================
%%% Roundtrip: encode → decode for every instruction family
%%% ===================================================================

alu64_imm_roundtrip_test_() ->
    Ops = [
        {add64_imm,  fun ebpf_insn:add64_imm/2},
        {sub64_imm,  fun ebpf_insn:sub64_imm/2},
        {mul64_imm,  fun ebpf_insn:mul64_imm/2},
        {div64_imm,  fun ebpf_insn:div64_imm/2},
        {or64_imm,   fun ebpf_insn:or64_imm/2},
        {and64_imm,  fun ebpf_insn:and64_imm/2},
        {lsh64_imm,  fun ebpf_insn:lsh64_imm/2},
        {rsh64_imm,  fun ebpf_insn:rsh64_imm/2},
        {mod64_imm,  fun ebpf_insn:mod64_imm/2},
        {xor64_imm,  fun ebpf_insn:xor64_imm/2},
        {mov64_imm,  fun ebpf_insn:mov64_imm/2},
        {arsh64_imm, fun ebpf_insn:arsh64_imm/2}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(3, 100),
        ?assertEqual({Name, 3, 0, 0, 100}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

alu64_reg_roundtrip_test_() ->
    Ops = [
        {add64_reg,  fun ebpf_insn:add64_reg/2},
        {sub64_reg,  fun ebpf_insn:sub64_reg/2},
        {mul64_reg,  fun ebpf_insn:mul64_reg/2},
        {div64_reg,  fun ebpf_insn:div64_reg/2},
        {or64_reg,   fun ebpf_insn:or64_reg/2},
        {and64_reg,  fun ebpf_insn:and64_reg/2},
        {lsh64_reg,  fun ebpf_insn:lsh64_reg/2},
        {rsh64_reg,  fun ebpf_insn:rsh64_reg/2},
        {mod64_reg,  fun ebpf_insn:mod64_reg/2},
        {xor64_reg,  fun ebpf_insn:xor64_reg/2},
        {mov64_reg,  fun ebpf_insn:mov64_reg/2},
        {arsh64_reg, fun ebpf_insn:arsh64_reg/2}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(2, 5),
        ?assertEqual({Name, 2, 5, 0, 0}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

neg64_roundtrip_test() ->
    ?assertEqual({neg64, 7, 0, 0, 0}, ebpf_insn:decode(ebpf_insn:neg64(7))).

alu32_imm_roundtrip_test_() ->
    Ops = [
        {add32_imm,  fun ebpf_insn:add32_imm/2},
        {sub32_imm,  fun ebpf_insn:sub32_imm/2},
        {mul32_imm,  fun ebpf_insn:mul32_imm/2},
        {div32_imm,  fun ebpf_insn:div32_imm/2},
        {or32_imm,   fun ebpf_insn:or32_imm/2},
        {and32_imm,  fun ebpf_insn:and32_imm/2},
        {lsh32_imm,  fun ebpf_insn:lsh32_imm/2},
        {rsh32_imm,  fun ebpf_insn:rsh32_imm/2},
        {mod32_imm,  fun ebpf_insn:mod32_imm/2},
        {xor32_imm,  fun ebpf_insn:xor32_imm/2},
        {mov32_imm,  fun ebpf_insn:mov32_imm/2},
        {arsh32_imm, fun ebpf_insn:arsh32_imm/2}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(1, 255),
        ?assertEqual({Name, 1, 0, 0, 255}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

alu32_reg_roundtrip_test_() ->
    Ops = [
        {add32_reg,  fun ebpf_insn:add32_reg/2},
        {sub32_reg,  fun ebpf_insn:sub32_reg/2},
        {mul32_reg,  fun ebpf_insn:mul32_reg/2},
        {div32_reg,  fun ebpf_insn:div32_reg/2},
        {or32_reg,   fun ebpf_insn:or32_reg/2},
        {and32_reg,  fun ebpf_insn:and32_reg/2},
        {lsh32_reg,  fun ebpf_insn:lsh32_reg/2},
        {rsh32_reg,  fun ebpf_insn:rsh32_reg/2},
        {mod32_reg,  fun ebpf_insn:mod32_reg/2},
        {xor32_reg,  fun ebpf_insn:xor32_reg/2},
        {mov32_reg,  fun ebpf_insn:mov32_reg/2},
        {arsh32_reg, fun ebpf_insn:arsh32_reg/2}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(6, 9),
        ?assertEqual({Name, 6, 9, 0, 0}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

neg32_roundtrip_test() ->
    ?assertEqual({neg32, 4, 0, 0, 0}, ebpf_insn:decode(ebpf_insn:neg32(4))).

%%% ===================================================================
%%% Memory instructions
%%% ===================================================================

ldx_roundtrip_test_() ->
    Ops = [
        {ldxw,  fun ebpf_insn:ldxw/3},
        {ldxh,  fun ebpf_insn:ldxh/3},
        {ldxb,  fun ebpf_insn:ldxb/3},
        {ldxdw, fun ebpf_insn:ldxdw/3}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(1, 10, 8),
        ?assertEqual({Name, 1, 10, 8, 0}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

stx_roundtrip_test_() ->
    Ops = [
        {stxw,  fun ebpf_insn:stxw/3},
        {stxh,  fun ebpf_insn:stxh/3},
        {stxb,  fun ebpf_insn:stxb/3},
        {stxdw, fun ebpf_insn:stxdw/3}
    ],
    [{atom_to_list(Name), fun() ->
        %% stx(Dst, Off, Src) → encoded as (Dst, Src, Off, 0)
        Bin = Fun(10, -8, 3),
        ?assertEqual({Name, 10, 3, -8, 0}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

st_roundtrip_test_() ->
    Ops = [
        {stw,  fun ebpf_insn:stw/3},
        {sth,  fun ebpf_insn:sth/3},
        {stb,  fun ebpf_insn:stb/3},
        {stdw, fun ebpf_insn:stdw/3}
    ],
    [{atom_to_list(Name), fun() ->
        Bin = Fun(10, -16, 99),
        ?assertEqual({Name, 10, 0, -16, 99}, ebpf_insn:decode(Bin))
    end} || {Name, Fun} <- Ops].

%%% ===================================================================
%%% 64-bit immediate loads
%%% ===================================================================

ld64_imm_roundtrip_test() ->
    Bin = ebpf_insn:ld64_imm(1, 16#DEADBEEFCAFE),
    {ld64_imm, 1, 0, 0, Imm} = ebpf_insn:decode(Bin),
    ?assertEqual(16#DEADBEEFCAFE, Imm).

ld_map_fd_roundtrip_test() ->
    Bin = ebpf_insn:ld_map_fd(2, 7),
    {ld_map_fd, 2, 1, 0, 7} = ebpf_insn:decode(Bin).

%%% ===================================================================
%%% Jump instructions
%%% ===================================================================

ja_roundtrip_test() ->
    ?assertEqual({ja, 0, 0, 5, 0}, ebpf_insn:decode(ebpf_insn:ja(5))).

jmp64_roundtrip_test_() ->
    Ops = [
        {jeq_imm,  fun ebpf_insn:jeq_imm/3,  imm},
        {jeq_reg,  fun ebpf_insn:jeq_reg/3,  reg},
        {jgt_imm,  fun ebpf_insn:jgt_imm/3,  imm},
        {jgt_reg,  fun ebpf_insn:jgt_reg/3,  reg},
        {jge_imm,  fun ebpf_insn:jge_imm/3,  imm},
        {jge_reg,  fun ebpf_insn:jge_reg/3,  reg},
        {jset_imm, fun ebpf_insn:jset_imm/3, imm},
        {jset_reg, fun ebpf_insn:jset_reg/3, reg},
        {jne_imm,  fun ebpf_insn:jne_imm/3,  imm},
        {jne_reg,  fun ebpf_insn:jne_reg/3,  reg},
        {jsgt_imm, fun ebpf_insn:jsgt_imm/3, imm},
        {jsgt_reg, fun ebpf_insn:jsgt_reg/3, reg},
        {jsge_imm, fun ebpf_insn:jsge_imm/3, imm},
        {jsge_reg, fun ebpf_insn:jsge_reg/3, reg},
        {jlt_imm,  fun ebpf_insn:jlt_imm/3,  imm},
        {jlt_reg,  fun ebpf_insn:jlt_reg/3,  reg},
        {jle_imm,  fun ebpf_insn:jle_imm/3,  imm},
        {jle_reg,  fun ebpf_insn:jle_reg/3,  reg},
        {jslt_imm, fun ebpf_insn:jslt_imm/3, imm},
        {jslt_reg, fun ebpf_insn:jslt_reg/3, reg},
        {jsle_imm, fun ebpf_insn:jsle_imm/3, imm},
        {jsle_reg, fun ebpf_insn:jsle_reg/3, reg}
    ],
    [{atom_to_list(Name), fun() ->
        case Mode of
            imm ->
                Bin = Fun(1, 42, 3),
                ?assertEqual({Name, 1, 0, 3, 42}, ebpf_insn:decode(Bin));
            reg ->
                Bin = Fun(1, 2, 3),
                ?assertEqual({Name, 1, 2, 3, 0}, ebpf_insn:decode(Bin))
        end
    end} || {Name, Fun, Mode} <- Ops].

jmp32_roundtrip_test_() ->
    Ops = [
        {jeq32_imm,  fun ebpf_insn:jeq32_imm/3,  imm},
        {jeq32_reg,  fun ebpf_insn:jeq32_reg/3,  reg},
        {jgt32_imm,  fun ebpf_insn:jgt32_imm/3,  imm},
        {jgt32_reg,  fun ebpf_insn:jgt32_reg/3,  reg},
        {jge32_imm,  fun ebpf_insn:jge32_imm/3,  imm},
        {jge32_reg,  fun ebpf_insn:jge32_reg/3,  reg},
        {jne32_imm,  fun ebpf_insn:jne32_imm/3,  imm},
        {jne32_reg,  fun ebpf_insn:jne32_reg/3,  reg},
        {jlt32_imm,  fun ebpf_insn:jlt32_imm/3,  imm},
        {jlt32_reg,  fun ebpf_insn:jlt32_reg/3,  reg},
        {jle32_imm,  fun ebpf_insn:jle32_imm/3,  imm},
        {jle32_reg,  fun ebpf_insn:jle32_reg/3,  reg},
        {jsgt32_imm, fun ebpf_insn:jsgt32_imm/3, imm},
        {jsgt32_reg, fun ebpf_insn:jsgt32_reg/3, reg},
        {jsge32_imm, fun ebpf_insn:jsge32_imm/3, imm},
        {jsge32_reg, fun ebpf_insn:jsge32_reg/3, reg},
        {jslt32_imm, fun ebpf_insn:jslt32_imm/3, imm},
        {jslt32_reg, fun ebpf_insn:jslt32_reg/3, reg},
        {jsle32_imm, fun ebpf_insn:jsle32_imm/3, imm},
        {jsle32_reg, fun ebpf_insn:jsle32_reg/3, reg},
        {jset32_imm, fun ebpf_insn:jset32_imm/3, imm},
        {jset32_reg, fun ebpf_insn:jset32_reg/3, reg}
    ],
    [{atom_to_list(Name), fun() ->
        case Mode of
            imm ->
                Bin = Fun(5, 77, -2),
                ?assertEqual({Name, 5, 0, -2, 77}, ebpf_insn:decode(Bin));
            reg ->
                Bin = Fun(5, 8, -2),
                ?assertEqual({Name, 5, 8, -2, 0}, ebpf_insn:decode(Bin))
        end
    end} || {Name, Fun, Mode} <- Ops].

%%% ===================================================================
%%% Special instructions
%%% ===================================================================

call_roundtrip_test() ->
    ?assertEqual({call, 0, 0, 0, 1}, ebpf_insn:decode(ebpf_insn:call(1))).

exit_roundtrip_test() ->
    ?assertEqual({exit_insn, 0, 0, 0, 0}, ebpf_insn:decode(ebpf_insn:exit_insn())).

%%% ===================================================================
%%% Negative offset / immediate
%%% ===================================================================

negative_offset_test() ->
    Bin = ebpf_insn:ldxw(1, 10, -4),
    ?assertEqual({ldxw, 1, 10, -4, 0}, ebpf_insn:decode(Bin)).

negative_imm_test() ->
    Bin = ebpf_insn:mov64_imm(0, -1),
    ?assertEqual({mov64_imm, 0, 0, 0, -1}, ebpf_insn:decode(Bin)).

%%% ===================================================================
%%% Assemble
%%% ===================================================================

assemble_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 0),
        ebpf_insn:exit_insn()
    ]),
    ?assertEqual(16, byte_size(Prog)).

assemble_empty_test() ->
    ?assertEqual(<<>>, ebpf_insn:assemble([])).

%%% ===================================================================
%%% Unknown opcode
%%% ===================================================================

unknown_opcode_test() ->
    %% 0xFF is not a valid BPF opcode
    Bin = <<16#FF, 0, 0:16/little, 0:32/little>>,
    ?assertMatch({{unknown, 16#FF}, 0, 0, 0, 0}, ebpf_insn:decode(Bin)).
