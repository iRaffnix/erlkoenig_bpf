defmodule ErlkoenigEbpfDsl.ExamplesTest do
  use ExUnit.Case, async: true

  @examples_dir Path.expand("../examples", __DIR__)

  for file <- Path.wildcard("#{@examples_dir}/*.ex") do
    basename = Path.basename(file, ".ex")

    # Extract module name from file content (first defmodule)
    @tag :examples
    test "example #{basename} compiles to valid BPF bytecode" do
      [{mod, _}] = Code.compile_file(unquote(file))
      assert {:ok, bin} = mod.compile()
      assert is_binary(bin)
      assert byte_size(bin) > 0
      # BPF instructions are 8 bytes each
      assert rem(byte_size(bin), 8) == 0
    end
  end
end
