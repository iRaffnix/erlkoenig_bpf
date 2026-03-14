%% @doc ALU execution for the BPF VM (ALU64 + ALU32).
-module(ebpf_vm_alu).

-export([exec/4]).

-define(MASK64, 16#FFFFFFFFFFFFFFFF).
-define(MASK32, 16#FFFFFFFF).

%% @doc Execute an ALU operation, return new register value.
exec(Op, DstVal, SrcVal, Width) ->
    Mask = case Width of 64 -> ?MASK64; 32 -> ?MASK32 end,
    Result = alu_op(Op, DstVal band Mask, SrcVal band Mask, Width),
    Result band Mask.

alu_op(add, A, B, _W)  -> A + B;
alu_op(sub, A, B, _W)  -> A - B;
alu_op(mul, A, B, _W)  -> A * B;
alu_op('div', A, B, _W) when B =/= 0 -> A div B;
alu_op('div', _, 0, _W) -> 0;   %% BPF semantics: div by zero -> 0
alu_op('or', A, B, _W)  -> A bor B;
alu_op('and', A, B, _W) -> A band B;
alu_op(lsh, A, B, W)  -> A bsl (B band shift_mask(W));
alu_op(rsh, A, B, W)  -> A bsr (B band shift_mask(W));
alu_op(neg, A, _, _W)  -> -A;
alu_op(mod, A, B, _W) when B =/= 0 -> A rem B;
alu_op(mod, _, 0, _W)  -> 0;    %% BPF semantics: mod by zero -> 0
alu_op('xor', A, B, _W) -> A bxor B;
alu_op(mov, _, B, _W)  -> B;
alu_op(arsh, A, B, W) -> signed_rsh(A, B band shift_mask(W), W).

%% BPF spec: shift amount is masked to 63 for 64-bit, 31 for 32-bit.
shift_mask(64) -> 63;
shift_mask(32) -> 31.

%% Arithmetic right shift: sign-extend using width-appropriate conversion.
signed_rsh(Val, Shift, Width) ->
    Signed = to_signed(Val, Width),
    Signed bsr Shift.

to_signed(V, 64) when V >= (1 bsl 63) -> V - (1 bsl 64);
to_signed(V, 32) when V >= (1 bsl 31) -> V - (1 bsl 32);
to_signed(V, _) -> V.
