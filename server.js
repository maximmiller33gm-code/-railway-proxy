const http = require('http');
const net = require('net');
const url = require('url');

const PORT = process.env.PORT || 8080;
const AUTH_USER = process.env.AUTH_USER || 'user';
const AUTH_PASS = process.env.AUTH_PASS || 'pass';

function unauthorized(res) {
  res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="RailwayProxy"' });
  res.end('Proxy authentication required');
}
function checkAuth(req, res) {
  if (!AUTH_USER) return true;
  const h = req.headers['proxy-authorization'] || req.headers['authorization'];
  if (!h || !h.startsWith('Basic ')) { unauthorized(res); return false; }
  const [u, p] = Buffer.from(h.slice(6), 'base64').toString().split(':');
  if (u === AUTH_USER && p === AUTH_PASS) return true;
  unauthorized(res); return false;
}

const server = http.createServer((req, res) => {
  if (!checkAuth(req, res)) return;
  const parsed = url.parse(req.url);
  const options = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: parsed.path,
    headers: { ...req.headers }
  };
  delete options.headers['proxy-authorization'];
  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on('error', (err) => { res.writeHead(502); res.end('Error: ' + err); });
  req.pipe(proxyReq);
});

server.on('connect', (req, client, head) => {
  const [host, port] = req.url.split(':');
  const target = net.connect(port || 443, host, () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    target.write(head); target.pipe(client); client.pipe(target);
  });
});

server.listen(PORT, () => console.log('Proxy started on port', PORT));
