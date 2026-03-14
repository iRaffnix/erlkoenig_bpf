# ICMP Rate Limiter: Ping-Floods erkennen und droppen.
# Zaehlt ICMP Echo Requests (type 8) pro Source-IP,
# ab 20 Requests wird gedroppt.

defmodule IcmpRateLimit do
  use ErlkoenigEbpfDsl.XDP

  xdp "icmp_rate_limit" do
    map :ping_count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_icmp do
      if icmp_type == @icmp_echo_request do
        count = map_lookup(ping_count, src_ip)
        new_count = count + 1
        map_update(ping_count, src_ip, new_count)
        if new_count > 20 do
          :drop
        else
          :pass
        end
      else
        :pass
      end
    end
  end
end
