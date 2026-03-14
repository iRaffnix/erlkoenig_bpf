%% @doc Decode BPF program binary into an array of vm_insn records.
-module(ebpf_vm_decode).

-include("ebpf_vm.hrl").

-export([decode_program/1]).

-spec decode_program(binary()) -> array:array(#vm_insn{}).
decode_program(Bin) ->
    Insns = decode_all(Bin, []),
    array:from_list(Insns).

decode_all(<<>>, Acc) ->
    lists:reverse(Acc);
%% 16-byte LD_IMM64 — consumes two instruction slots
decode_all(<<16#18, SrcDst, Off:16/signed-little, ImmLo:32/signed-little,
             0, 0, 0:16/little, ImmHi:32/signed-little, Rest/binary>>, Acc) ->
    Dst = SrcDst band 16#0F,
    Src = (SrcDst bsr 4) band 16#0F,
    Imm = (ImmHi bsl 32) bor (ImmLo band 16#FFFFFFFF),
    Op = case Src of
        1 -> ld_map_fd;
        2 -> ld_map_value;
        _ -> ld64_imm
    end,
    Insn = #vm_insn{op = Op, dst = Dst, src = Src, off = Off, imm = Imm},
    %% LD_IMM64 occupies two slots; add a nop placeholder for the second
    Nop = #vm_insn{op = nop, dst = 0, src = 0, off = 0, imm = 0},
    decode_all(Rest, [Nop, Insn | Acc]);
%% Standard 8-byte instruction
decode_all(<<Code, SrcDst, Off:16/signed-little, Imm:32/signed-little,
             Rest/binary>>, Acc) ->
    Dst = SrcDst band 16#0F,
    Src = (SrcDst bsr 4) band 16#0F,
    {Op, _Dst2, _Src2, _Off2, _Imm2} = ebpf_insn:decode(<<Code, SrcDst, Off:16/signed-little, Imm:32/signed-little>>),
    Insn = #vm_insn{op = Op, dst = Dst, src = Src, off = Off, imm = Imm},
    decode_all(Rest, [Insn | Acc]).
