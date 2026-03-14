# Minimales XDP-Programm: Alle Pakete durchlassen.
#
# Kompilieren:
#   iex -S mix
#   > HelloPass.compile()
#   {:ok, <<...>>}

defmodule HelloPass do
  use ErlkoenigEbpfDsl.XDP

  xdp "hello_pass" do
    main do
      :pass
    end
  end
end
