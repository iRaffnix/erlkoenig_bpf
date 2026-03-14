# XDP-Programm: Alle Pakete droppen (Blackhole).
#
# Nuetzlich als Ausgangsbasis fuer selektives Whitelisting.

defmodule DropAll do
  use ErlkoenigEbpfDsl.XDP

  xdp "drop_all" do
    main do
      :drop
    end
  end
end
