# Network-path follow-up — 2026-10-19

**Additional confirmed VM findings from the network itself: 0.** The original two NIC findings remain point-in-time hardware measurements from17:32CEST; this follow-up did not reread the NIC. It performed new network measurements from19:55CEST onward using user-mode sockets, Windows networking APIs and built-in Packet Monitor. It did not load another custom driver, change signing policy or reboot.

The network fits a quiet subnet behind a dnsmasq-speaking router, with another private LAN upstream. That is compatible with host-managed VM networking. A physical Windows PC behind an equivalent Linux router could reproduce the observations, so they are recorded as lab/infrastructure clues rather than promoted to VM proof. In particular, identifying a virtual or software-managed gateway would not by itself prove the client is virtual.

## Gateway DNS and DHCP

Seven UDP/TCP CHAOS/TXT `version.bind` responses returned **dnsmasq-2.93**. `authors.bind` returned **Simon Kelley**. The guest's reverse DNS record returned its existing Windows hostname. Hostname/server-ID queries yielded no VM-specific identifier. Version strings are configurable and do not authenticate the server binary.

Exact example:

```text
request_hex: 7ad3010000010000000000000776657273696f6e0462696e640000100003
response_hex: 7ad3858000010001000000000776657273696f6e0462696e640000100003c00c0010000300000000000d0c646e736d6173712d322e3933
```

Five unicast **DHCPINFORM** requests received ACKs. All used the existing guest IP/MAC and a fresh transaction ID. The ACK options were consistently **53,54,1,28,3,6**: message type, server identifier, netmask, broadcast, router and DNS. They supplied192.168.1.1 as router/DNS/server, without hostname, domain, bootfile or vendor-specific VM marker. INFORM requests parameters without acquiring an address; no DHCPREQUEST, RELEASE, NAK injection or lease change was issued. See [RFC2131](https://www.rfc-editor.org/rfc/rfc2131), sections3.4/4.3.5.

The [dnsmasq project](https://thekelleys.org.uk/dnsmasq/doc.html) supports these functions on ordinary routers. This service fingerprint is not exclusive to libvirt, QEMU or virtual clients. The previously observed DNS TTL1 was not a fixed behavior: fresh queries returned ordinary cached TTLs, including201 seconds from the gateway. Direct UDP and TCP queries to1.1.1.1 and8.8.8.8 worked with distinct replies. Transparent rewriting of all tested DNS destinations was not established.

## Path, forwarding and transport controls

Native Windows ping consistently reported:

```text
TTL1: Reply from 192.168.1.1: TTL expired in transit.
TTL2: Reply from 192.168.0.1: TTL expired in transit.
TTL3: Reply from 83.178.5.194: TTL expired in transit.
```

Both1.1.1.1 and8.8.8.8 produced the same first three hops. Record Route to1.1.1.1 twice began with **192.168.0.9**, followed by public upstream addresses. The decoded option bytes are preserved; the first response contained:

```text
072728c0a8000953fd97c453b205c25b81001aac44b401ac44b4140101010101010101ac44b41400
```

This exposes an upstream private interface and is consistent with routing/NAT between the guest subnet and another LAN. It does not identify the router's physical/virtual implementation or prove that192.168.0.9 is the hypervisor. DNS queries to192.168.0.9 timed out; no host-service identity was obtained. The [router requirements](https://www.rfc-editor.org/rfc/rfc1812) explain TTL expiry and IP-option processing on physical routers as well.

DNS TCP SYN-ACKs retained destination-specific fingerprints:

- Gateway192.168.1.1: TTL64, window64240, MSS1460, scale10.
- Cloudflare1.1.1.1: TTL52, window65535, MSS1460, scale13.
- Google8.8.8.8: TTL104, window65535, MSS1412, scale8 in the first capture.

TCP53 to the gateway succeeded even with outgoing TTL1; remote TCP53 timed out at TTL1 and succeeded at TTL64. ICMP echo replies also had different remote TTLs. These observations do not show one synthetic TCP endpoint replacing all destinations. Public [libslirp code](https://raw.githubusercontent.com/utmapp/libslirp/master/src/ip_icmp.c) provides an emulated echo path and assigns MAXTTL when reflecting packets. The observed behavior argues against a simple stock Slirp fingerprint; it cannot exclude a customized proxy. No Slirp pseudo-ping string or VM identifier was recovered.

The gateway filtered ICMP echo and seven tested non-DNS TCP ports. Public ICMP data remained intact. A DF echo with1472 bytes of payload succeeded;1473 was rejected locally by Windows with WinError10040. A corrected **2000-byte payload** echoed successfully and matched every byte after reassembly; the reply was2028 IP bytes, with on-capture fragments of1500 and548 bytes sharing an IP ID. Normal fragmentation/reassembly is a control, not VM evidence.

## Local-link discovery

Nine selected ARP targets were tested:1,2,3,10,50,100,200,253,254 in192.168.1.0/24. Only192.168.1.1 answered, with MACc4:e9:84:3a:7f:b2. The MAC was not a stock QEMU prefix. No proxy-ARP replies for all unused addresses were found.

Three bounded multicast DNS service queries, one SSDP root-device search and an IPv6 all-nodes echo received no answers. This is compatible with a filtered or quiet VLAN and does not establish that the segment lacks physical devices. No whole-subnet scan or multicast flood was performed. Neighbor-cache entries created by normal probes are transient; persistent neighbor/route/adapter settings were not edited.

## Infrastructure disclosure excluded from VM evidence

The gateway's `servers.bind` response disclosed:

```text
100.100.100.100#53 3709 0
fd7a:115c:a1e0::53#53 190 0
```

The resolver addresses match [Tailscale's documented resolver infrastructure](https://tailscale.com/docs/reference/quad100). This establishes a DNS configuration disclosure, not which machine runs Tailscale or whether it is part of the review tooling. It is conservatively classified **tooling**, excluded from the VM count. No credentials, tailnet login, private configuration or direct queries to those overlay resolvers were used. One short MAC-only capture includes unrelated HTTPS traffic; those frames are excluded tooling and unused in findings.

## Evidence quality and unresolved controls

Four bounded capture rounds are preserved as ETL and pcapng, along with full raw request/response hex in JSONL. DNS/DHCP API responses are available even where capture omitted frames. **Packet Monitor did not capture every successful exchange**: some local DNS/DHCP traffic and outbound frames were absent, including in a MAC-only filter control and an all-component capture. Those omissions are unresolved instrumentation limitations, not proof of virtual networking.

The custom raw-ICMP socket did not receive several errors that Packet Monitor captured. Native Windows ping subsequently received the expected hop replies. Therefore, raw-socket timeouts were not interpreted as network suppression. The initial oversized-payload generator produced1805 rather than2000 bytes; the generator was fixed and a separate2000-byte byte-for-byte control passed. The packet decoder was also fixed to avoid interpreting noninitial IP fragments as transport headers. Original raw evidence remains untouched.

`NET-LAB-02` records gateway/path observations; `NET-TOOL-03` records overlay DNS disclosure. Both include exact commands, source expectations, access, raw evidence and limitations in the root `findings.jsonl`. The root total remains **2 prior hardware findings**, excluding all clues/lab/tooling; this follow-up adds **0 confirmed VM findings**.

## Reproduction, changes and final state

Run the four preserved `src/network-*-capture.ps1` scripts named in the new records with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`. They run the Python probes and remove their temporary Packet Monitor filters after stopping capture. Use `src/parse-network-capture.py` with capture names `capture`, `path`, `discovery`, `mac-control`; then run `src/append-network-findings.py` to verify byte equality, decode routing data and append records. `raw/network-deep/analysis.json` contains the structured result. The exact C driver and prior binary remain unchanged.

All changes are recorded in the root `changes.log`. This follow-up added scripts, raw captures, public reference downloads and report data. It temporarily activated built-in Packet Monitor and added filters, restoring its initially stopped/no-filter state after each round. It made no persistent guest security, network, firewall, signing or driver changes. No new development tools, certificate or kernel service was installed. No discovered credentials or tokens were used.

Final verification at **20:04CEST** is preserved in `raw/network-deep/security-final.txt`, `module-final.txt` and `pktmon-final.txt`: Secure Boot off; code integrity enabled with options0x00000001; test signing/nointegritychecks absent; VBS/HVCI off; firewall profiles enabled. **Probe driver remains unloaded**, its service remains absent, Packet Monitor is stopped and its filters are empty.
