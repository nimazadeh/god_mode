import { connect } from "cloudflare:sockets";

// Authenticate X-Aether-Token and synthesize IETF RFC 6052 NAT64 IPv6 targets so the personal Worker routes 100% of destinations.
const AETHER_SECRET = "aethergate-rfc9421-personal-master-key-2026";
const NAT64_US_PREFIX = "2602:fc59:b0:64::";

function ipv4ToNat64(ipv4) {
  const parts = ipv4.trim().split(".");
  if (parts.length !== 4) return ipv4;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return ipv4;
  const hi = ((nums[0] << 8) | nums[1]).toString(16).padStart(4, "0");
  const lo = ((nums[2] << 8) | nums[3]).toString(16).padStart(4, "0");
  return `[${NAT64_US_PREFIX}${hi}:${lo}]`;
}

async function toBytes(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data && typeof data.arrayBuffer === "function") return new Uint8Array(await data.arrayBuffer());
  return new Uint8Array(0);
}

export default {
  async fetch(request, env) {
    const expectedToken = (env && env.AETHER_SECRET) ? env.AETHER_SECRET : AETHER_SECRET;
    const clientToken = request.headers.get("x-aether-token") || "";
    if (clientToken !== expectedToken) {
      return new Response("AetherGate Personal Serverless Node v11.7 Ready", { status: 200 });
    }
    const targetHeader = request.headers.get("x-aether-target") || "";
    const splitIndex = targetHeader.lastIndexOf(":");
    if (splitIndex <= 0) {
      return new Response("Missing X-Aether-Target", { status: 400 });
    }
    const rawHost = targetHeader.slice(0, splitIndex);
    const port = Number(targetHeader.slice(splitIndex + 1)) || 443;
    const useNat64 = request.headers.get("x-aether-nat64") === "1";
    const hostname = useNat64 ? ipv4ToNat64(rawHost) : rawHost;
    let tcpSocket;
    try {
      tcpSocket = connect({ hostname, port });
    } catch {
      tcpSocket = connect({ hostname: ipv4ToNat64(rawHost), port });
    }
    if (tcpSocket.opened) tcpSocket.opened.catch(() => {});
    if (tcpSocket.closed) tcpSocket.closed.catch(() => {});
    const [clientWs, serverWs] = Object.values(new WebSocketPair());
    // Set binaryType to arraybuffer before accept() per Cloudflare 2026-03-17 websocket_standard_binary_type docs.
    serverWs.binaryType = "arraybuffer";
    serverWs.accept();
    const tcpWriter = tcpSocket.writable.getWriter();
    serverWs.addEventListener("message", async (event) => {
      try {
        const chunk = await toBytes(event.data);
        if (chunk.byteLength > 0) await tcpWriter.write(chunk);
      } catch {
        try { serverWs.close(1011, "write error"); } catch {}
      }
    });
    serverWs.addEventListener("close", () => {
      try { tcpSocket.close(); } catch {}
    });
    (async () => {
      const reader = tcpSocket.readable.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          serverWs.send(value);
        }
      } catch {} finally {
        try { serverWs.close(); } catch {}
      }
    })();
    return new Response(null, { status: 101, webSocket: clientWs });
  }
};
