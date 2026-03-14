# Protocol Profiler: Pakete und Bytes pro IP-Protokoll zaehlen.
# Portiert von C/XDP xdp_profiler.
#
# Original nutzt BPF_MAP_TYPE_PERCPU_ARRAY mit struct datarec.
# Wir nutzen zwei separate Hash-Maps (packets + bytes) als Workaround,
# da die DSL keine Struct-Values und kein percpu_array unterstuetzt.

defmodule ProtocolProfiler do
  use ErlkoenigEbpfDsl.XDP

  xdp "protocol_profiler" do
    map :proto_packets, :hash, key: :u32, value: :u64, max_entries: 256
    map :proto_bytes,   :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv4 do
      pkts = map_lookup(proto_packets, protocol)
      map_update(proto_packets, protocol, pkts + 1)

      bytes = map_lookup(proto_bytes, protocol)
      map_update(proto_bytes, protocol, bytes + total_length)

      :pass
    end
  end
end
