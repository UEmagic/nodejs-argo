const express = require("express");
const app = express();
const os = require('os');
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require('util');
const { spawn } = require('child_process');
const exec = promisify(require('child_process').exec);

// ================= 核心配置项 =================
const FILE_PATH = process.env.FILE_PATH || '.tmp';
const SUB_PATH = process.env.SUB_PATH || 'my-mac-sub-1984';
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || 3000, 10);
const ARGO_PORT = parseInt(process.env.ARGO_PORT || 8001, 10);
const UUID = process.env.UUID || '448ecbf7-b396-4df5-86c1-5139589b668f'; 

// ⚠️⚠️⚠️ 请务必把下面两行的内容，改回你自己的真实域名和 Token！ ⚠️⚠️⚠️
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || 'uesd.uemagic.dpdns.org';
const ARGO_AUTH = process.env.ARGO_AUTH || 'eyJhIjoiMDM1NWQ1Yzk0MDUzYzVjMmQ4YjgwNWYwNGY5NjYzM2MiLCJ0IjoiMWM3ZjQyMTEtZmRlZS00OGZhLWE2ODItZDJlNGRjZGI3ZGI3IiwicyI6IlpUVTRNemRoTURrdFlqbGpaQzAwTm1NeExUazJOVEl0WkRNNE9HUXpORGd3TURNMyJ9'; 

const CFIP = process.env.CFIP || 'uesd.uemagic.dpdns.org';
const CFPORT = process.env.CFPORT || 443;
const NAME = process.env.NAME || 'SafeNode';

const webPath = path.join(FILE_PATH, 'web');
const botPath = path.join(FILE_PATH, 'bot');
const subPath = path.join(FILE_PATH, 'sub.txt');
const bootLogPath = path.join(FILE_PATH, 'boot.log');

if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} created`);
}

// 【修复 1】全面开启日志输出！如果出错，在 DCDEPLOY 的 LOGS 里一目了然
function spawnProcess(command, args, name) {
  const child = spawn(command, args);
  child.stdout.on('data', (data) => console.log(`[${name}] ${data.toString().trim()}`));
  child.stderr.on('data', (data) => console.error(`[${name} ERROR] ${data.toString().trim()}`));
  child.on('close', (code) => console.log(`[${name}] exited with code ${code}`));
  child.on('error', (err) => console.error(`[${name} FAILED]`, err.message));
}

async function generateConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'warning' },
    inbounds: [
      // 【修复 2】回落目标改为动态 PORT，防止平台内部端口不是 3000 导致连接拒绝
      { port: ARGO_PORT, protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none', fallbacks: [{ dest: PORT }, { path: "/vless-argo", dest: 3002 }, { path: "/vmess-argo", dest: 3003 }, { path: "/trojan-argo", dest: 3004 }] }, streamSettings: { network: 'tcp' } },
      { port: 3001, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID }], decryption: "none" }, streamSettings: { network: "tcp", security: "none" } },
      { port: 3002, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID, level: 0 }], decryption: "none" }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/vless-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { port: 3003, listen: "127.0.0.1", protocol: "vmess", settings: { clients: [{ id: UUID, alterId: 0 }] }, streamSettings: { network: "ws", wsSettings: { path: "/vmess-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { port: 3004, listen: "127.0.0.1", protocol: "trojan", settings: { clients: [{ password: UUID }] }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/trojan-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
    ],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [ { protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "block" } ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        { type: "field", ip: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"], outboundTag: "block" }
      ]
    }
  };
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

// 【修复 3】加入 ghproxy 加速节点，防止 DCDEPLOY 被 Github 限速导致下载失败
async function downloadOfficialBinaries() {
  const arch = os.arch();
  const isArm = (arch === 'arm' || arch === 'arm64' || arch === 'aarch64');
  const xrayArch = isArm ? 'arm64-v8a' : '64';
  const cfArch = isArm ? 'arm64' : 'amd64';

  if (!fs.existsSync(botPath)) {
    try {
      console.log("Downloading Cloudflared...");
      await exec(`wget -qO ${botPath} https://ghproxy.net/https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cfArch}`);
      await exec(`chmod 775 ${botPath}`);
    } catch (e) {
      console.error("Cloudflared download error:", e.message);
    }
  }

  if (!fs.existsSync(webPath)) {
    try {
      console.log("Downloading Xray...");
      await exec(`wget -qO ${FILE_PATH}/xray.zip https://ghproxy.net/https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xrayArch}.zip`);
      await exec(`unzip -qo ${FILE_PATH}/xray.zip -d ${FILE_PATH}`);
      await exec(`mv ${FILE_PATH}/xray ${webPath}`);
      await exec(`chmod 775 ${webPath}`);
      await exec(`rm -f ${FILE_PATH}/xray.zip ${FILE_PATH}/geoip.dat ${FILE_PATH}/geosite.dat ${FILE_PATH}/LICENSE ${FILE_PATH}/README.md`);
      console.log("Xray setup completed.");
    } catch (e) {
      console.error("Xray download/unzip error:", e.message);
    }
  }
}

function setupArgoConfig() {
  if (ARGO_AUTH.includes('TunnelSecret')) {
    try {
      const authData = JSON.parse(ARGO_AUTH);
      fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
      const tunnelYaml = `
tunnel: ${authData.TunnelSecret}
credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://127.0.0.1:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
    } catch (err) {}
  }
}

async function extractDomains() {
  let argoDomain = ARGO_DOMAIN;
  if (!argoDomain) {
    try {
      const fileContent = fs.readFileSync(bootLogPath, 'utf-8');
      const lines = fileContent.split('\n');
      for (const line of lines) {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) { argoDomain = domainMatch[1]; break; }
      }
    } catch (error) {}
  }
  if (argoDomain) { await generateLinks(argoDomain); } 
  else { setTimeout(extractDomains, 5000); }
}

async function generateLinks(argoDomain) {
  const nodeName = `${NAME}-Node`;
  const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'};
  
  const subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
`;

  const encodedSub = Buffer.from(subTxt).toString('base64');
  fs.writeFileSync(subPath, encodedSub);
  
  app.get(`/${SUB_PATH}`, (req, res) => {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.send(encodedSub);
  });
}

async function startServer() {
  try {
    setupArgoConfig();
    await generateConfig();
    await downloadOfficialBinaries();

    if (fs.existsSync(webPath)) {
      spawnProcess(webPath, ['-c', path.join(FILE_PATH, 'config.json')], 'XRAY');
    } else {
      console.error("[FATAL] Xray executable not found! Download must have failed.");
    }

    if (fs.existsSync(botPath)) {
      let args = [];
      if (ARGO_AUTH.startsWith('ey')) {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH];
      } else if (ARGO_AUTH.includes('TunnelSecret')) {
        args = ['tunnel', '--edge-ip-version', 'auto', '--config', path.join(FILE_PATH, 'tunnel.yml'), 'run'];
      } else {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', '--logfile', bootLogPath, '--loglevel', 'info', '--url', `http://127.0.0.1:${ARGO_PORT}`];
      }
      spawnProcess(botPath, args, 'CLOUDFLARED');
      setTimeout(extractDomains, 5000);
    } else {
      console.error("[FATAL] Cloudflared executable not found! Download must have failed.");
    }
  } catch (error) {
    console.error("Server start error:", error);
  }
}

startServer();

app.get("/", (req, res) => {
  const htmlPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(htmlPath)) { res.sendFile(htmlPath); } 
  else { res.send("Welcome to CodeFlow API Server."); }
});

app.listen(PORT, () => console.log(`[NODEJS] HTTP server listening on port ${PORT}`));
