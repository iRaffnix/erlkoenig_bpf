# Port Firewall: Nur Pakete an erlaubte TCP/UDP Ports durchlassen.
# Nicht-TCP/UDP wird von on_tcp/on_udp automatisch mit :pass durchgelassen.
# Hier: nur TCP-Ports filtern (fuer UDP analog mit on_udp).

defmodule PortFirewall do
  use ErlkoenigEbpfDsl.XDP

  xdp "port_firewall" do
    map :allowed_ports, :hash, key: :u32, value: :u64, max_entries: 1024

    on_tcp do
      allowed = map_lookup(allowed_ports, dst_port)
      if allowed != 0 do
        :pass
      else
        :drop
      end
    end
  end
end
