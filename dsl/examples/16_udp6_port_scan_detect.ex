# UDP6 Port Scan Detection: Zaehlt wie viele unterschiedliche
# Ziel-Ports eine IPv6-Source anspricht. Hohe Zahlen deuten
# auf Port-Scanning hin.

defmodule Udp6PortScanDetect do
  use ErlkoenigEbpfDsl.XDP

  xdp "udp6_port_scan" do
    map :port_hits, :hash, key: :u32, value: :u64, max_entries: 65536

    on_udp6 do
      count = map_lookup(port_hits, src_ip6_lo)
      new_count = count + 1
      map_update(port_hits, src_ip6_lo, new_count)
      if new_count > 200 do
        :drop
      else
        :pass
      end
    end
  end
end
