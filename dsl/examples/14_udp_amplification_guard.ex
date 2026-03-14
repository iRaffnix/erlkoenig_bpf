# UDP Amplification Guard: Grosse UDP-Pakete von bekannten
# Amplification-Ports (DNS 53, NTP 123, SSDP 1900) zaehlen
# und bei Schwellwert droppen.

defmodule UdpAmplificationGuard do
  use ErlkoenigEbpfDsl.XDP

  xdp "udp_amp_guard" do
    map :amp_count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_udp do
      if udp_length > 512 do
        if src_port == @port_dns || src_port == @port_ntp || src_port == @port_ssdp do
          count = map_lookup(amp_count, src_ip)
          new_count = count + 1
          map_update(amp_count, src_ip, new_count)
          if new_count > 10 do
            :drop
          else
            :pass
          end
        else
          :pass
        end
      else
        :pass
      end
    end
  end
end
