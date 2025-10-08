import http from "http";
import net from "net";
import url from "url";

const PORT = process.env.PORT || 8080;

// базовая авторизация: задаёшь эти переменные в Railway → Variables
const AUTH_USER = process.env.PROXY_USER || "";
const AUTH_PASS = process.env.PROXY_PASS || "";

function checkAuth(req) {
  if (!AUTH_USER && !AUTH_PASS) return true; // без пароля — не советую в проде
  const hdr = req.headers["proxy-authorization"] || req.headers["authorization"];
  if (!hdr || !hdr.startsWith("Basic ")) return false;
  const decoded = Buffer.from(hdr.slice(6), "base64").toString();
  // формат user:pass
  return decoded === `${AUTH_USER}:${AUTH_PASS}`;
}

function send407(res) {
  res.writeHead(407, {
    "Proxy-Authenticate": "Basic realm=\"railway-proxy\"",
    "Content-Type": "text/plain; charset=utf-8"
  });
  res.end("407 Proxy Authentication Required");
}

// --- обычные HTTP-запросы через прокси ---
const server = http.createServer((clientReq, clientRes) => {
  if (!checkAuth(clientReq)) return send407(clientRes);

  const parsed = url.parse(clientReq.url);
  const options = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
    method: clientReq.method,
    path: parsed.path,
    headers: clientReq.headers,
    timeout: 20000
  };

  const proxyReq = http.request(options, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });

  proxyReq.on("timeout", () => {
    proxyReq.destroy(new Error("upstream timeout"));
  });

  proxyReq.on("error", (err) => {
    clientRes.writeHead(502, { "Content-Type": "text/plain" });
    clientRes.end("Bad Gateway: " + (err?.message || "error"));
  });

  clientReq.pipe(proxyReq);
});

// --- HTTPS через CONNECT-tуннель ---
server.on("connect", (req, clientSocket, head) => {
  if (!checkAuth(req)) {
    clientSocket.write(
      "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"railway-proxy\"\r\n\r\n"
    );
    clientSocket.destroy();
    return;
  }

  // req.url вида "host:port"
  const [host, portStr] = (req.url || "").split(":");
  const port = parseInt(portStr || "443", 10) || 443;

  const upstream = net.connect(port, host, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });

  const kill = (err) => {
    try { clientSocket.destroy(); } catch {}
    try { upstream.destroy(); } catch {}
  };

  upstream.setTimeout(20000, () => kill(new Error("upstream timeout")));
  upstream.on("error", kill);
  clientSocket.on("error", kill);
});

server.listen(PORT, () => {
  console.log(`HTTP proxy listening on ${PORT}`);
});
