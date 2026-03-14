# Bandwidth Monitor: Bytes pro Source-IP zaehlen.

defmodule BandwidthMonitor do
  use ErlkoenigEbpfDsl.XDP

  xdp "bandwidth_monitor" do
    map :bytes_per_ip, :hash, key: :u32, value: :u64, max_entries: 65536

    on_ipv4 do
      current = map_lookup(bytes_per_ip, src_ip)
      map_update(bytes_per_ip, src_ip, current + total_length)
      :pass
    end
  end
end
