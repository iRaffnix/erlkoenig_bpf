defmodule ErlkoenigEbpfDsl do
  @moduledoc """
  Elixir DSL frontend for the erlkoenig eBPF compiler.

  Translates Elixir macro-based XDP program definitions into
  EBL AST tuples and compiles them through the Erlang pipeline.
  """

  @doc "Compile an EBL AST (as Erlang tuples) through the pipeline."
  def compile(ast) do
    case :ebl_typecheck.check(ast) do
      {:ok, typed} ->
        ir = :ebpf_ir_gen.generate(typed)
        {reg_map, spill_map} = :ebpf_regalloc.allocate(ir)
        bin = :ebpf_codegen.codegen(ir, reg_map, spill_map)
        {:ok, :ebpf_peephole.optimize(bin)}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Compile Elixir DSL source code (as a string) into BPF bytecode.
  The last expression must evaluate to an EBL AST tuple.
  """
  def compile_string(source) do
    case eval_to_ast(source) do
      {:ok, ast} -> compile(ast)
      {:error, _} = err -> err
    end
  end

  @doc """
  Compile Elixir DSL source and return all intermediate artifacts
  (same format as ebl_compile:compile_debug/1).
  """
  def compile_debug_string(source) do
    case eval_to_ast(source) do
      {:ok, ast} ->
        case :ebl_typecheck.check(ast) do
          {:ok, typed} ->
            ir = :ebpf_ir_gen.generate(typed)
            {reg_map, spill_map} = :ebpf_regalloc.allocate(ir)
            bin = :ebpf_codegen.codegen(ir, reg_map, spill_map)
            ir_blocks = :ebpf_ir_format.format(ir)

            {:ok, %{binary: bin, ir: ir_blocks,
                    regmap: reg_map, spillmap: spill_map,
                    source_map: %{}}}

          {:error, errs} ->
            {:error, %{formatted: :ebl_error_format.format(errs),
                       json: :ebl_error_format.format_json(errs)}}
        end

      {:error, _} = err ->
        err
    end
  end

  defp eval_to_ast(source) do
    try do
      {result, _bindings} = Code.eval_string(source)

      case result do
        {:program, _, _, _, _, _, _, _} ->
          {:ok, result}

        _ ->
          {:error, %{formatted: "Elixir code must evaluate to an EBL AST (program tuple)",
                     json: %{message: "Elixir code must evaluate to an EBL AST",
                             line: 0, col: 0, phase: "elixir"}}}
      end
    rescue
      e ->
        msg = Exception.message(e)
        {:error, %{formatted: msg,
                   json: %{message: msg, line: 0, col: 0, phase: "elixir"}}}
    end
  end
end
