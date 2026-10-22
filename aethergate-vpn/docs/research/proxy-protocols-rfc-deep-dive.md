# Deep-Dive Architecture of Proxy Protocols: SOCKS5 (RFC 1928/1929), HTTP Proxy (RFC 9110/9112/9298), and Telegram MTProto (`obfuscated2` / `dd` / `ee` Fake-TLS)

## 1. SOCKS5 Protocol (`RFC 1928` & `RFC 1929`)
- **Primary Specifications**:
  - [RFC 1928 — SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928.txt) (March 1996)
  - [RFC 1929 — Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929.txt) (March 1996)
- **Architectural Layer**: Session-layer (`Layer 5`) shim between the application layer and transport layer (`TCP` / `UDP`). Protocol-agnostic: once the tunnel is established, raw bytes flow transparently without application headers.
- **Wire State Machine**:
  1. **Greeting / Method Negotiation**:
     - Client -> Server: `+----+----------+----------+` (`VER = 0x05`, `NMETHODS = 1..255`, `METHODS = [0x00 No-Auth, 0x01 GSSAPI, 0x02 User/Pass, ...]`)
     - Server -> Client: `+----+--------+` (`VER = 0x05`, `METHOD = selected or 0xFF if rejected`)
  2. **Optional Sub-Negotiation (`RFC 1929` when `METHOD == 0x02`)**:
     - Client -> Server: `VER(0x01) | ULEN(1) | UNAME | PLEN(1) | PASSWD`
     - Server -> Client: `VER(0x01) | STATUS(0x00 = OK)`
  3. **Command Request**:
     - Client -> Server: `VER(0x05) | CMD(1) | RSV(0x00) | ATYP(1) | DST.ADDR(var) | DST.PORT(2, big-endian)`
     - Commands (`CMD`):
       - `0x01` (`CONNECT`): Outbound TCP stream tunnel.
       - `0x02` (`BIND`): Inbound secondary connection (designed for protocols like passive/active FTP).
       - `0x03` (`UDP ASSOCIATE`): Allocates a UDP relay port (`BND.ADDR:BND.PORT`) tied to the lifetime of the control TCP socket.
     - Address Types (`ATYP`):
       - `0x01`: 4-byte IPv4 literal (`socket.inet_aton`).
       - `0x03`: Length-prefixed FQDN (`[1-byte len][ASCII domain]` — enables remote DNS resolution `socks5h://` without local DNS leaks).
       - `0x04`: 16-byte IPv6 literal.
  4. **Server Reply**:
     - Server -> Client: `VER(0x05) | REP(0x00 = succeeded, 0x01..0x08 = error) | RSV(0x00) | ATYP | BND.ADDR | BND.PORT`
  5. **UDP Relay Framing (`Section 7`)**:
     - Every UDP datagram sent to `BND.PORT` is prefixed with: `RSV(0x0000, 2B) | FRAG(1B) | ATYP(1B) | DST.ADDR(var) | DST.PORT(2B) | DATA`.

## 2. HTTP Proxy (`RFC 9110`, `RFC 9112`, and `RFC 9298` MASQUE)
- **Primary Specifications**:
  - [RFC 9110 — HTTP Semantics (Section 9.3.6 `CONNECT`)](https://www.rfc-editor.org/rfc/rfc9110.html) (June 2022)
  - [RFC 9112 — HTTP/1.1 (Section 3.2.2 `absolute-form`, Section 3.2.3 `authority-form`, Section 6.3)](https://www.rfc-editor.org/rfc/rfc9112.html) (June 2022)
  - [RFC 9298 — Proxying UDP in HTTP (`connect-udp` / MASQUE)](https://www.rfc-editor.org/rfc/rfc9298.txt) (August 2022)
- **Two Distinct Modes**:
  1. **Forward Proxy Mode (`absolute-form`, `RFC 9112 Section 3.2.2`)**:
     - Used for plaintext HTTP (`GET http://example.com/index.html HTTP/1.1`).
     - The proxy parses the full HTTP message, strips hop-by-hop headers (`Proxy-Authorization`, `Proxy-Connection`), appends `Via:` (`RFC 9110 Section 7.6.3`), and forwards the reconstructed HTTP request.
  2. **Tunnel Mode (`CONNECT` with `authority-form`, `RFC 9110 Section 9.3.6` & `RFC 9112 Section 3.2.3`)**:
     - Client -> Proxy:
       ```http
       CONNECT example.com:443 HTTP/1.1\r\n
       Host: example.com:443\r\n
       \r\n
       ```
     - Proxy opens raw TCP to `example.com:443` and replies:
       ```http
       HTTP/1.1 200 Connection Established\r\n
       \r\n
       ```
     - Per `RFC 9112 Section 6.3 Rule 2`: *"Any 2xx (Successful) response to a CONNECT request implies that the connection will become a tunnel immediately after the empty line that concludes the header fields. A client MUST ignore any Content-Length or Transfer-Encoding header fields received in such a message."*
  3. **UDP over HTTP (`RFC 9298` — `connect-udp` / MASQUE)**:
     - Extends HTTP/1.1 (`Upgrade: connect-udp`), HTTP/2, and HTTP/3 (`Extended CONNECT`, `:protocol = connect-udp`) using URI templates (`/.well-known/masque/udp/{target_host}/{target_port}/`) and HTTP Datagrams (`RFC 9297`) to tunnel UDP (including QUIC) over HTTP.

## 3. Telegram MTProto Proxy (`obfuscated2`, `dd` Padded Intermediate, and `ee` Fake-TLS)
- **Primary References**:
  - [Telegram MTProto Transports Specification](https://core.telegram.org/mtproto/mtproto-transports)
  - [seriyps/mtproto_proxy Fake-TLS & Policy Architecture](https://github.com/seriyps/personal_mtproxy/blob/master/priv/ARTICLE.md)
  - [sanyok12345/teleproto Issue #42 — Fake-TLS ClientHello HMAC & Timestamp XOR](https://github.com/sanyok12345/teleproto/issues/42)
- **Evolution Across Three Generations**:
  1. **Generation 1 — Plain `obfuscated2` (32-hex / 16-byte secret)**:
     - Client generates a 64-byte random initialization buffer `init[0..63]`:
       - Bytes `8..39` (32 bytes): Client-to-Server `encrypt_key`
       - Bytes `40..55` (16 bytes): Client-to-Server `encrypt_iv`
       - Reversed bytes `8..55` yield the Server-to-Client `decrypt_key` and `decrypt_iv`.
       - In MTProxy mode, the actual `AES-256-CTR` key is derived as `SHA256(encrypt_key[0..31] || secret[0..15])`.
       - Bytes `56..59` contain the transport tag (`0xefefefef` Abridged, `0xeeeeeeee` Intermediate, or `0xdddddddd` Padded Intermediate), and bytes `60..61` contain the signed 16-bit Telegram `dc_id` (`1..5`).
       - The client encrypts all 64 bytes with `AES-256-CTR`, then sends `init[0..55] (plaintext) || encrypted_init[56..63] (8 bytes)`.
     - **Weakness**: DPI middleboxes detected the fixed 64-byte handshake burst and packet-length distribution.
  2. **Generation 2 — `dd`-Prefixed Secret (`SecretSecured` — `PaddedIntermediate` `0xdddddddd`)**:
     - Secret starts with `dd` + 32 hex chars (`17 bytes` total).
     - Enforces the `PaddedIntermediate` transport tag (`0xdddddddd`) inside `init[56..59]` and appends `0..15` random padding bytes to every MTProto frame (`receiver strips length % 4`) to defeat packet-size fingerprinting.
     - **Weakness**: Still begins with high-entropy raw `AES-CTR` ciphertext on port 443 without a TLS header, which modern Iranian/Russian DPI blocks as "unknown high-entropy protocol on TCP/443".
  3. **Generation 3 — `ee`-Prefixed Secret (`SecretFakeTLS` — Fake-TLS 1.3 + Domain Fronting)**:
     - Secret format: `0xee || <16-byte secret> || <UTF-8 SNI hostname in hex>` (e.g., `ee<32-hex><hex("www.cloudflare.com")>`).
     - **Step 1 (Fake TLS 1.3 `ClientHello`)**:
       - Client constructs a byte-accurate TLS 1.3 `ClientHello` (`0x16 0x03 0x01 ...`) whose `server_name` (SNI) extension is set to the domain encoded in the `ee` secret, plus X25519 `key_share`, `supported_versions` (`TLS 1.3`), and `GREASE` extensions matching Chrome/Firefox.
       - Inside the 32-byte `ClientHello.Random` field (`offset 11..42`):
         - The client zeros out `Random`, computes `digest = HMAC-SHA256(key=secret, msg=ClientHello_with_zeroed_random)`.
         - Writes `digest[0..27]` into the first 28 bytes of `Random`.
         - Writes `digest[28..31] XOR uint32_le(unix_timestamp)` into the last 4 bytes of `Random`!
     - **Step 2 (O(1) Server Verification & Active-Probe Camouflage / Domain Fronting)**:
       - When the MTProxy server receives a `ClientHello`, it computes `HMAC-SHA256(key=secret, msg=ClientHello_with_zeroed_random)`, XORs the last 4 bytes with `Random[28..31]`, and checks if the extracted `unix_timestamp` is within the allowed clock-skew window AND not in the anti-replay Bloom filter!
       - **If verification FAILS** (e.g., an Iranian/Russian GFW active probe, a replay attack, or a normal browser): the server **transparently splices/forwards the TCP connection to the real SNI host** (e.g., `www.cloudflare.com:443`)! The censor receives a real TLS 1.3 handshake + real X.509 certificate signed by DigiCert/Let's Encrypt from the real domain!
       - **If verification SUCCEEDS**: the server replies with `ServerHello (0x16) || ChangeCipherSpec (0x14) || ApplicationData (0x17)` signed with `HMAC-SHA256(secret, ClientHello.Random || ServerResponse_with_zeroed_random)`.
     - **Step 3 (TLS Record Wrapping + `obfuscated2`)**:
       - After the Fake-TLS handshake completes, the client sends the 64-byte `obfuscated2` (`0xdddddddd`) stream wrapped inside standard TLS `0x17 0x03 0x03` (`Application Data`) records, making the entire session indistinguishable from TLS 1.3 on the wire.
