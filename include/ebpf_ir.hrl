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

%% ebpf_ir.hrl — Intermediate Representation for the EBL→BPF compiler
-ifndef(EBPF_IR_HRL).
-define(EBPF_IR_HRL, true).

%% ===================================================================
%% Virtual Registers
%% ===================================================================

%% Virtual register: {v, N} for general, plus distinguished regs.
%% {clobber, Idx, R} is a synthetic vreg used by the regalloc to model
%% that helper calls destroy R1-R5 at instruction index Idx.
-type vreg() ::
    {v, non_neg_integer()}
    | v_ctx
    | v_fp
    | v_ret
    | {clobber, non_neg_integer(), 1..5}.

%% Physical BPF register (post-allocation)
-type preg() :: 0..10.

%% Register (virtual or physical depending on pipeline stage)
-type reg() :: vreg() | preg().

%% ===================================================================
%% IR Types (carried on every register)
%% ===================================================================

-type ir_type() ::
    {scalar, u8 | u16 | u32 | u64 | i8 | i16 | i32 | i64 | bool}
    | {ptr, ptr_kind()}
    | {option, ir_type()}
    | action
    | void.

-type ptr_kind() :: ctx | packet | stack | map_value | map_key.

%% ===================================================================
%% IR Instructions
%% ===================================================================

-record(ir_instr, {
    op :: ir_op(),
    dst :: reg() | none,
    args :: [reg() | integer() | atom() | tuple()],
    type :: ir_type(),
    loc :: {pos_integer(), non_neg_integer()} | undefined
}).

-type ir_op() ::
    %% Arithmetic
    mov
    | mov32
    | add
    | sub
    | mul
    | 'div'
    | mod
    | and_op
    | or_op
    | xor_op
    | lsh
    | rsh
    | arsh
    | neg
    | not_op
    %% Endian
    | endian_be
    %% Memory
    | load
    | store
    | store_imm
    %% Map / helper
    | call_helper
    | ld_map_fd
    %% Safety
    | bounds_check
    | null_check
    %% SSA
    | phi
    %% No-op
    | nop.

%% ===================================================================
%% Terminators (one per basic block, always last)
%% ===================================================================

-type cmp_op() :: eq | ne | gt | ge | lt | le.

-type terminator() ::
    {br, label()}
    | {cond_br, reg(), label(), label()}
    | {cond_br, {cmp, cmp_op(), reg(), reg()}, label(), label()}
    | {exit, reg()}
    | unreachable.

-type label() :: {label, non_neg_integer()} | entry.

%% ===================================================================
%% Basic Block
%% ===================================================================

-record(ir_block, {
    label :: label(),
    phis = [] :: [#ir_instr{}],
    instrs = [] :: [#ir_instr{}],
    term :: terminator()
}).

%% ===================================================================
%% IR Program (complete compilation unit)
%% ===================================================================

-record(ir_program, {
    prog_type :: xdp | tc | cgroup | socket,
    name :: binary(),
    maps = [] :: [ir_map_def()],
    entry :: label(),
    blocks = #{} :: #{label() => #ir_block{}},
    reg_types = #{} :: #{reg() => ir_type()},
    next_reg = 0 :: non_neg_integer(),
    next_label = 0 :: non_neg_integer(),
    source_map = #{} :: #{non_neg_integer() => {pos_integer(), non_neg_integer()}}
}).

-type ir_map_def() :: #{
    name := binary(),
    kind := atom(),
    key_type := ir_type(),
    val_type := ir_type(),
    max_entries := non_neg_integer()
}.

%% ===================================================================
%% Action value mapping per program type
%% ===================================================================

-define(XDP_ABORTED, 0).
-define(XDP_DROP, 1).
-define(XDP_PASS, 2).
-define(XDP_TX, 3).
-define(XDP_REDIRECT, 4).

-define(TC_OK, 0).
-define(TC_RECLASSIFY, 1).
-define(TC_SHOT, 2).
-define(TC_PIPE, 3).

%% EBPF_IR_HRL
-endif.
