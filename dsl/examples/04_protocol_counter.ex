# Protocol Counter: Pakete nach IP-Protokoll zaehlen.

defmodule ProtocolCounter do
  use ErlkoenigEbpfDsl.XDP

  xdp "protocol_counter" do
    map :counters, :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv4 do
      count = map_lookup(counters, protocol)
      map_update(counters, protocol, count + 1)
      :pass
    end
  end
end
