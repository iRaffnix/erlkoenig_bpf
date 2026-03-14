# IPv6 Filter: Hop-Limit Statistik pro Wert zaehlen.

defmodule Ipv6Filter do
  use ErlkoenigEbpfDsl.XDP

  xdp "ipv6_filter" do
    map :hop_stats, :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv6 do
      count = map_lookup(hop_stats, hop_limit)
      map_update(hop_stats, hop_limit, count + 1)
      :pass
    end
  end
end
