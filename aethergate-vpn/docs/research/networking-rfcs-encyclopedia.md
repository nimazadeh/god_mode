# Complete Encyclopedia of Core Networking, Security, Proxy & Anti-Censorship RFCs (1969 – 2026)

This document catalogs the foundational and cutting-edge IETF Request for Comments (RFCs) across all layers of modern networking, cryptography, DNS privacy, HTTP semantics, and censorship circumvention.

---

## Layer 1 & 2: Internet Addressing, Routing & Core IP Architecture

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 791** | Internet Protocol (`IPv4`) | 1981 | Defines the 20-byte IPv4 header, TTL, fragmentation, and best-effort packet delivery. |
| **RFC 792** | Internet Control Message Protocol (`ICMP`) | 1981 | Defines network diagnostic and control messages (`Echo Request/Reply`, `Destination Unreachable`, `Time Exceeded`). |
| **RFC 1918** | Address Allocation for Private Internets | 1996 | Reserves `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` for private LANs (used by AetherGate's `SovereignLanGateway` ACL). |
| **RFC 2460 / RFC 8200** | Internet Protocol, Version 6 (`IPv6`) | 2017 | Defines the 128-bit address space, simplified 40-byte fixed header, and minimum `1280-byte` link MTU. |
| **RFC 4271** | A Border Gateway Protocol 4 (`BGP-4`) | 2006 | Inter-Autonomous System (`AS`) routing protocol that glues global ISPs and Anycast CDNs (`Cloudflare`, `Google GFE`) together. |
| **RFC 4786** | Operation of Anycast Services | 2006 | Explains how multiple global edge nodes share a single IP (`104.18.14.206`, `216.239.38.120`) announced via BGP. |

---

## Layer 3: Transport Protocols (`TCP`, `UDP`, `QUIC`, `MPTCP`, `Happy Eyeballs`)

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 768** | User Datagram Protocol (`UDP`) | 1980 | Stateless 8-byte header datagram transport with zero handshake latency. |
| **RFC 9293** | Transmission Control Protocol (`TCP`) | 2022 | Consolidates 41 years of TCP updates since `RFC 793` (SYN/SYN-ACK/ACK 3-way handshake, congestion window, Nagle's algorithm `TCP_NODELAY`, and sequence reassembly). |
| **RFC 8305** | Happy Eyeballs Version 2 | 2017 | Races multiple candidate endpoints/IPs in parallel with staggered timers so dead routes never stall connection startup. |
| **RFC 8684** | TCP Extensions for Multipath Operation (`MPTCP`) | 2020 | Splits a single logical TCP stream across multiple network interfaces (e.g., Wi-Fi + Cellular simultaneously). |
| **RFC 9000** | QUIC: A UDP-Based Multiplexed and Secure Transport | 2021 | Integrates TLS 1.3 into UDP with independent stream multiplexing, `0-RTT`/`1-RTT` handshakes, and Connection ID migration across Wi-Fi/LTE IP changes. |
| **RFC 9001** | Using TLS to Secure QUIC | 2021 | Specifies how TLS 1.3 handshake records are carried inside QUIC `CRYPTO` frames and how initial packets are obfuscated. |
| **RFC 9221** | An Unreliable Datagram Extension to QUIC | 2022 | Adds unreliable `DATAGRAM` frames inside an encrypted QUIC connection (the foundation of `MASQUE` VPN tunnels). |

---

## Layer 4: Modern Cryptography, TLS 1.3 & Encrypted Client Hello (`ECH`)

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 7748** | Elliptic Curves for Security (`X25519` & `X448`) | 2016 | Defines constant-time Montgomery ladder key agreement over `Curve25519` (`p = 2^255 - 19`, `a24 = 121665`). |
| **RFC 8439** | ChaCha20 and Poly1305 for IETF Protocols | 2018 | High-speed ARX stream cipher + MAC ideal for mobile CPUs without AES hardware acceleration. |
| **RFC 8446** | The Transport Layer Security (`TLS`) Protocol Version 1.3 | 2018 | 1-RTT handshake, mandatory forward secrecy, encrypted certificates after `ServerHello`, and Section 5.1 Record Layer framing (used by AetherGate's Polymorphic SNI Shredder). |
| **RFC 9180** | Hybrid Public Key Encryption (`HPKE`) | 2022 | Standardizes public-key encryption combining KEM (`X25519`), KDF (`HKDF`), and AEAD (`AES-GCM`/`ChaCha20Poly1305`). |
| **RFC 9848** | Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings | 2026 | Specifies publishing `ECHConfigList` public keys inside DNS `HTTPS`/`SVCB` records. |
| **RFC 9849** | TLS Encrypted Client Hello (`ECH`) | 2026 | Finalizes `draft-ietf-tls-esni-25`: splits `ClientHello` into an innocuous public `ClientHelloOuter` and an HPKE-encrypted `ClientHelloInner` that completely hides the real SNI and ALPN from DPI middleboxes. |

---

## Layer 5: DNS Architecture & Next-Gen Encrypted/Oblivious DNS

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 1035** | Domain Names - Implementation and Specification | 1987 | Classic UDP/TCP port 53 DNS wire format (vulnerable to ISP DNS poisoning into `10.10.34.*`). |
| **RFC 7858** | Specification for DNS over Transport Layer Security (`DoT`) | 2016 | Encrypts DNS over TCP port `853` (easily blocked by port-based ISP firewalls). |
| **RFC 8484** | DNS Queries over HTTPS (`DoH`) | 2018 | Encapsulates DNS queries inside standard HTTPS `GET`/`POST` on port `443` (`/dns-query`), blending DNS into web traffic. |
| **RFC 9230** | Oblivious DNS over HTTPS (`ODoH`) | 2022 | Decouples client IP from DNS query content using an Oblivious Relay + HPKE-encrypted Target Resolver so no single server knows both *who* asked and *what* domain was queried. |
| **RFC 9250** | DNS over Dedicated QUIC Connections (`DoQ`) | 2022 | Runs encrypted DNS over QUIC with independent streams and zero head-of-line blocking. |
| **RFC 9460** | Service Binding and Parameter Specification via the DNS (`SVCB` and `HTTPS` RRs) | 2023 | Allows DNS to return protocol hints (`h3`, `alpn`), alternative ports, IP hints, and `ECH` public keys in a single lookup. |

---

## Layer 6: HTTP Evolution, Caching & Cryptographic Message Signatures

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 7838** | HTTP Alternative Services (`Alt-Svc`) | 2016 | Server header advertising QUIC/`h3` upgrades on UDP `:443` (stripped by AetherGate when UDP QUIC is blackholed by the ISP). |
| **RFC 8441** | Bootstrapping WebSockets with HTTP/2 | 2018 | Enables bidirectional WebSocket tunnels inside multiplexed HTTP/2 streams. |
| **RFC 9110** | HTTP Semantics | 2022 | Defines unified HTTP methods, status codes, headers, and Section 9.3.6 `CONNECT` tunneling (including `502 Bad Gateway` fast-fail semantics). |
| **RFC 9111** | HTTP Caching | 2022 | Defines `Cache-Control`, `Age`, `ETag`, `stale-while-revalidate`, and `stale-if-error` (implemented in AetherGate's Zero-Redis Cache). |
| **RFC 9112** | HTTP/1.1 | 2022 | Defines wire-level HTTP/1.1 message syntax and `Transfer-Encoding: chunked` streaming. |
| **RFC 9113** | HTTP/2 | 2022 | Binary framing layer (`DATA`, `HEADERS`, `SETTINGS`, and `PADDED` flag `0x08` used by AetherGate to defeat packet-length DPI classifiers). |
| **RFC 9114** | HTTP/3 | 2022 | Maps HTTP semantics onto QUIC (`RFC 9000`) with `QPACK` header compression (`RFC 9204`). |
| **RFC 9421** | HTTP Message Signatures | 2024 | Cryptographically signs `@method`, `@target-uri`, `content-digest`, `created`, and `nonce` to defeat active DPI probing and replay attacks. |
| **RFC 9530** | Digest Fields | 2024 | Integrity verification via `Content-Digest: sha-256=:...:` structured byte-sequences. |
| **RFC 9651** | Structured Field Values for HTTP | 2024 | Strict, parser-safe typed dictionaries, lists, and byte sequences (`:base64:`) for modern HTTP headers. |

---

## Layer 7: Proxy, Tunneling & Privacy Relay Protocols (`SOCKS5`, `MASQUE`, `OHTTP`)

| RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 1928** | SOCKS Protocol Version 5 | 1996 | Protocol-agnostic TCP/UDP proxy at OSI Layer 5 supporting IPv4 (`0x01`), Domain (`0x03`), and IPv6 (`0x04`) addressing. |
| **RFC 1929** | Username/Password Authentication for SOCKS V5 | 1996 | Subnegotiation (`0x02`) for authenticated SOCKS5 relays. |
| **RFC 9298** | Proxying UDP in HTTP (`MASQUE CONNECT-UDP`) | 2022 | Tunnels UDP datagrams over HTTP/2 or HTTP/3 using URI templates (`/.well-known/masque/udp/{host}/{port}/`). |
| **RFC 9458** | Oblivious HTTP (`OHTTP`) | 2024 | Uses HPKE (`RFC 9180`) + a two-hop Relay/Gateway architecture (used by Apple Private Relay) so the Relay sees only your IP and the Gateway sees only your HTTP request. |
| **RFC 9484** | Proxying IP in HTTP (`MASQUE CONNECT-IP`) | 2023 | Turns any HTTP/2 or HTTP/3 server into a full Layer-3 IP VPN gateway (`/.well-known/masque/ip/`) capable of carrying raw IPv4/IPv6 packets inside HTTP Datagrams. |

---

## Layer 8: Anti-Fingerprinting, Cryptographic Anonymity & Information Theory (`JA4+`, `GREASE`, `Privacy Pass`)

| Standard / RFC | Title | Year | Core Mechanism & Engineering Takeaway |
| :--- | :--- | :--- | :--- |
| **RFC 8701** | Applying Generate Random Extensions And Sustain Extensibility (`GREASE`) to TLS | 2020 | Reserves 16 values (`0x0a0a`, `0x1a1a`, ..., `0xfafa` where `(v & 0x0f0f) == 0x0a0a`) injected randomly by Chrome into ciphers, extensions, ALPN, and versions to prevent middlebox ossification. |
| **RFC 8446 §4.2** | TLS 1.3 Extension Permutation (BoringSSL / Chrome 110+) | 2023 | Permutes TLS `ClientHello` extension ordering on every handshake (keeping `pre_shared_key` `0x0029` last), breaking static `JA3` MD5 fingerprinting. |
| **FoxIO JA4+** | `JA4` / `JA4S` / `JA4H` / `JA4T` Network Fingerprinting | 2023–2026 | Defeats extension permutation by sorting non-GREASE cipher suites and extensions (`excluding 0x0000 SNI & 0x0010 ALPN`) into `t13d1516h2_<sha256_ciphers>_<sha256_exts_sigalgs>`. |
| **RFC 9576 / 9577 / 9578** | The Privacy Pass Architecture, HTTP Auth Scheme & Blind-RSA Issuance | 2024 | Unlinkable cryptographic blind-RSA tokens (`Authorization: PrivateToken`) used by Cloudflare Turnstile to attest human browsers without cross-origin tracking cookies. |
| **Shannon $H(X)$ & $D_{KL}$** | Information Entropy & Kullback-Leibler Statistical Indistinguishability | 1948–2026 | $H(X) = -\sum P(x)\log_2 P(x)$ and $D_{KL}(P \parallel Q) = 0$: true anti-fingerprinting requires zero statistical divergence from the 2-billion-user Chrome anonymity set rather than synthetic anomalies. |

