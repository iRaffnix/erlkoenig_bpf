defmodule ErlkoenigEbpfDsl.IntegrationTest do
  use ExUnit.Case, async: true

  describe "DSL produces same bytecode as EBL" do
    test "minimal pass program" do
      ebl_source = "xdp test do\n  fn main(ctx) -> action do\n    return :pass\n  end\nend"
      {:ok, ebl_bin} = :ebl_compile.compile(ebl_source)

      state = ErlkoenigEbpfDsl.Builder.new("test")
      state = ErlkoenigEbpfDsl.Builder.set_main(state, quote(do: :pass))
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)
      {:ok, dsl_bin} = ErlkoenigEbpfDsl.compile(ast)

      assert ebl_bin == dsl_bin
    end

    test "minimal drop program" do
      ebl_source = "xdp test do\n  fn main(ctx) -> action do\n    return :drop\n  end\nend"
      {:ok, ebl_bin} = :ebl_compile.compile(ebl_source)

      state = ErlkoenigEbpfDsl.Builder.new("test")
      state = ErlkoenigEbpfDsl.Builder.set_main(state, quote(do: :drop))
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)
      {:ok, dsl_bin} = ErlkoenigEbpfDsl.compile(ast)

      assert ebl_bin == dsl_bin
    end

    test "program with map declaration" do
      ebl_source = """
      xdp test do
        map :counters, hash, key: u32, value: u64, max_entries: 1024
        fn main(ctx) -> action do
          return :pass
        end
      end
      """
      {:ok, ebl_bin} = :ebl_compile.compile(ebl_source)

      state = ErlkoenigEbpfDsl.Builder.new("test")
      state = ErlkoenigEbpfDsl.Builder.add_map(state, :counters, :hash,
        key: :u32, value: :u64, max_entries: 1024)
      state = ErlkoenigEbpfDsl.Builder.set_main(state, quote(do: :pass))
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)
      {:ok, dsl_bin} = ErlkoenigEbpfDsl.compile(ast)

      assert ebl_bin == dsl_bin
    end

    test "program with arithmetic" do
      ebl_source = """
      xdp test do
        fn main(ctx) -> action do
          let x = 1 + 2
          return :pass
        end
      end
      """
      {:ok, ebl_bin} = :ebl_compile.compile(ebl_source)

      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = 1 + 2
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)
      {:ok, dsl_bin} = ErlkoenigEbpfDsl.compile(ast)

      assert ebl_bin == dsl_bin
    end

    test "program with conditional" do
      ebl_source = """
      xdp test do
        fn main(ctx) -> action do
          let data = ctx.data
          let data_end = ctx.data_end
          if data + 34 > data_end do
            return :drop
          end
          return :pass
        end
      end
      """
      {:ok, ebl_bin} = :ebl_compile.compile(ebl_source)

      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        data = ctx.data
        data_end = ctx.data_end
        if data + 34 > data_end do
          :drop
        end
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)
      {:ok, dsl_bin} = ErlkoenigEbpfDsl.compile(ast)

      assert ebl_bin == dsl_bin
    end
  end

  describe "compile_string" do
    test "evaluates Elixir code to produce bytecode" do
      source = """
      import ErlkoenigEbpfDsl.Builder
      state = new("test")
      state = set_main(state, quote(do: :pass))
      to_ast(state)
      """
      assert {:ok, bin} = ErlkoenigEbpfDsl.compile_string(source)
      assert is_binary(bin)
      assert byte_size(bin) > 0
    end

    test "returns error for invalid Elixir" do
      assert {:error, %{formatted: msg}} = ErlkoenigEbpfDsl.compile_string("this is not valid")
      assert is_binary(msg)
    end

    test "returns error for code that doesn't produce an AST" do
      assert {:error, %{formatted: msg}} = ErlkoenigEbpfDsl.compile_string("1 + 1")
      assert msg =~ "AST"
    end
  end

  describe "compile_debug_string" do
    test "returns all intermediate artifacts" do
      source = """
      import ErlkoenigEbpfDsl.Builder
      state = new("test")
      state = set_main(state, quote(do: :pass))
      to_ast(state)
      """
      assert {:ok, result} = ErlkoenigEbpfDsl.compile_debug_string(source)
      assert is_binary(result.binary)
      assert is_list(result.ir)
      assert is_map(result.source_map)
    end
  end
end
