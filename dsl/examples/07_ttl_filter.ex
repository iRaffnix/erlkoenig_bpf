# TTL Filter: Pakete mit verdaechtig niedrigem TTL droppen.

defmodule TtlFilter do
  use ErlkoenigEbpfDsl.XDP

  xdp "ttl_filter" do
    map :ttl_stats, :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv4 do
      count = map_lookup(ttl_stats, ttl)
      map_update(ttl_stats, ttl, count + 1)

      if ttl <= 2 do
        :drop
      else
        :pass
      end
    end
  end
end
