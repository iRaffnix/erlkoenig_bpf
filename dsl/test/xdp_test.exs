defmodule ErlkoenigEbpfDsl.XDPTest do
  use ExUnit.Case, async: true

  describe "Builder" do
    test "creates a minimal XDP AST" do
      state = ErlkoenigEbpfDsl.Builder.new("test_prog")
      state = ErlkoenigEbpfDsl.Builder.set_main(state, quote(do: :pass))
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      assert {:program, :xdp, "test_prog", :undefined, [], [], [], [main_fn]} = ast
      assert {:fn_decl, "main", [{"ctx", :undefined}], {:prim, :action}, _body, {0, 0}} = main_fn
    end

    test "adds a map declaration" do
      state = ErlkoenigEbpfDsl.Builder.new("test_prog")
      state = ErlkoenigEbpfDsl.Builder.add_map(state, :counters, :hash,
        key: :u32, value: :u64, max_entries: 1024)
      state = ErlkoenigEbpfDsl.Builder.set_main(state, quote(do: :pass))
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      assert {:program, :xdp, _, _, [], [map_decl], [], _} = ast
      assert {:map_decl, "counters", :hash, {:prim, :u32}, {:prim, :u64}, 1024, {0, 0}} = map_decl
    end

    test "translates integer literal" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = 42
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, [let_stmt, return_stmt], _} = fn_decl
      assert {:let_stmt, {:var_pat, "x"}, {:integer_lit, 42, {0, 0}}, {0, 0}} = let_stmt
      assert {:return_stmt, {:atom_lit, "pass", {0, 0}}, {0, 0}} = return_stmt
    end

    test "translates if statement" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        if true do
          :drop
        else
          :pass
        end
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, [if_stmt], _} = fn_decl
      assert {:if_stmt, {:bool_lit, true, _}, _then, [], _else, _} = if_stmt
    end

    test "translates binary operations" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = 1 + 2
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, [let_stmt | _], _} = fn_decl
      {:let_stmt, _, expr, _} = let_stmt
      assert {:binop, :+, {:integer_lit, 1, _}, {:integer_lit, 2, _}, _} = expr
    end

    test "translates function calls" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = read_u16_be(data, 12)
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body, auto_bounds: false)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, [let_stmt | _], _} = fn_decl
      {:let_stmt, _, expr, _} = let_stmt
      assert {:call, "read_u16_be", [_, {:integer_lit, 12, _}], _} = expr
    end

    test "auto-inserts bounds check after data_end binding" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        data = ctx.data
        data_end = ctx.data_end
        x = read_u32_be(data, 26)
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, stmts, _} = fn_decl
      # User wrote data + data_end, bounds check inserted after data_end
      [data_let, data_end_let, bounds_if | user_stmts] = stmts
      assert {:let_stmt, {:var_pat, "data"}, {:field_access, {:var, "ctx", _}, "data", _}, _} = data_let
      assert {:let_stmt, {:var_pat, "data_end"}, {:field_access, {:var, "ctx", _}, "data_end", _}, _} = data_end_let
      assert {:if_stmt, {:binop, :>, {:binop, :+, _, {:integer_lit, 30, _}, _}, _, _}, _, _, _, _} = bounds_if
      # User statements follow
      assert [{:let_stmt, _, {:call, "read_u32_be", _, _}, _}, {:return_stmt, _, _}] = user_stmts
    end

    test "no bounds check without data_end binding" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = 42
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, stmts, _} = fn_decl
      assert [{:let_stmt, _, {:integer_lit, 42, _}, _}, {:return_stmt, _, _}] = stmts
    end

    test "no bounds check without read calls even with data_end" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        data = ctx.data
        data_end = ctx.data_end
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, stmts, _} = fn_decl
      # No bounds check — only user code
      assert [{:let_stmt, {:var_pat, "data"}, _, _},
              {:let_stmt, {:var_pat, "data_end"}, _, _},
              {:return_stmt, _, _}] = stmts
    end

    test "translates field access" do
      state = ErlkoenigEbpfDsl.Builder.new("test")
      body = quote do
        x = ctx.data
        :pass
      end
      state = ErlkoenigEbpfDsl.Builder.set_main(state, body)
      ast = ErlkoenigEbpfDsl.Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, [let_stmt | _], _} = fn_decl
      {:let_stmt, _, expr, _} = let_stmt
      assert {:field_access, {:var, "ctx", _}, "data", _} = expr
    end
  end
end
