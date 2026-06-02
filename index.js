const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

// ================= 核心配置项 =================
const FILE_PATH = process.env.FILE_PATH || '.tmp';       // 运行目录
const SUB_PATH = process.env.SUB_PATH || 'sub';          // 订阅路径 (访问 /sub 获取节点)
const PORT = process.env.SERVER_PORT || process.env.PORT || 3000; // http服务端口
const UUID = process.env.UUID || '448ecbf7-b396-4df5-86c1-5139589b668f'; 
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';       // 固定隧道域名,留空即启用临时隧道
const ARGO_AUTH = process.env.ARGO_AUTH || '';           // 固定隧道密钥json或token
const ARGO_PORT = process.env.ARGO_PORT || 8001;         // 本地隧道代理端口
const CFIP = process.env.CFIP || 'www.visa.com.sg';      // 节点优选域名或优选ip  
const CFPORT = process.env.CFPORT || 443;                // 优选端口
const NAME = process.env.NAME || 'SafeNode';             // 节点基础名称

// 取消随机进程名，使用固定名称方便系统进程排查
const webPath = path.join(FILE_PATH, 'web'); // Xray 内核
const botPath = path.join(FILE_PATH, 'bot'); // Cloudflared
const subPath = path.join(FILE_PATH, 'sub.txt');
const bootLogPath = path.join(FILE_PATH, 'boot.log');

// 初始化运行目录
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} created`);
}

// 生成 Xray 配置文件
async function generateConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [
      { port: ARGO_PORT, protocol: 'vless', settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none', fallbacks: [{ dest: 3001 }, { path: "/vless-argo", dest: 3002 }, { path: "/vmess-argo", dest: 3003 }, { path: "/trojan-argo", dest: 3004 }] }, streamSettings: { network: 'tcp' } },
      { port: 3001, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID }], decryption: "none" }, streamSettings: { network: "tcp", security: "none" } },
      { port: 3002, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID, level: 0 }], decryption: "none" }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/vless-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { port: 3003, listen: "127.0.0.1", protocol: "vmess", settings: { clients: [{ id: UUID, alterId: 0 }] }, streamSettings: { network: "ws", wsSettings: { path: "/vmess-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { port: 3004, listen: "127.0.0.1", protocol: "trojan", settings: { clients: [{ password: UUID }] }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/trojan-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
    ],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [ { protocol: "freedom", tag: "direct" }, {protocol: "blackhole", tag: "block"} ]
  };
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

// 判断架构并从官方渠道下载二进制文件
async function downloadOfficialBinaries() {
  const arch = os.arch();
  const isArm = (arch === 'arm' || arch === 'arm64' || arch === 'aarch64');
  
  const xrayArch = isArm ? 'arm64-v8a' : '64';
  const cfArch = isArm ? 'arm64' : 'amd64';

  // 下载 Cloudflared (官方源)
  if (!fs.existsSync(botPath)) {
    console.log("Downloading official Cloudflared...");
    try {
      await exec(`wget -qO ${botPath} https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cfArch}`);
      await exec(`chmod 775 ${botPath}`);
    } catch (e) {
      console.error("Cloudflared download failed. Ensure wget is installed.", e.message);
    }
  }

  // 下载 Xray (官方源，需依赖 unzip)
  if (!fs.existsSync(webPath)) {
    console.log("Downloading official Xray-core...");
    try {
      await exec(`wget -qO- https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xrayArch}.zip | unzip -qd ${FILE_PATH} -`);
      await exec(`mv ${FILE_PATH}/xray ${webPath}`);
      await exec(`chmod 775 ${webPath}`);
      // 清理残留的解压文件
      await exec(`rm -f ${FILE_PATH}/geoip.dat ${FILE_PATH}/geosite.dat ${FILE_PATH}/LICENSE ${FILE_PATH}/README.md`);
    } catch (e) {
      console.error("Xray download failed. Ensure wget and unzip are installed.", e.message);
    }
  }
}

// 配置固定隧道 Json
function setupArgoConfig() {
  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
tunnel: ${ARGO_AUTH.split('"')[11]}
credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  }
}

// 提取临时域名并生成节点信息
async function extractDomains() {
  let argoDomain = ARGO_DOMAIN;

  if (!argoDomain) {
    try {
      const fileContent = fs.readFileSync(bootLogPath, 'utf-8');
      const lines = fileContent.split('\n');
      for (const line of lines) {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          argoDomain = domainMatch[1];
          break;
        }
      }
    } catch (error) {
      console.error('Error reading boot.log for temp domain.', error.message);
    }
  }

  if (argoDomain) {
    console.log('ArgoDomain successfully fetched:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    console.log('ArgoDomain not found yet, will check again later...');
  }
}

// 获取公网 ISP 信息
async function getMetaInfo() {
  try {
    const response = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
    if (response.data && response.data.country_code && response.data.isp) {
      return `${response.data.country_code}-${response.data.isp}`.replace(/\s+/g, '_');
    }
  } catch (error) {
    // 静默忽略
  }
  return 'Unknown_ISP';
}

// 生成节点链接
async function generateLinks(argoDomain) {
  const ISP = await getMetaInfo();
  const nodeName = `${NAME}-${ISP}`;
  
  const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'};
  
  const subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
`;

  const encodedSub = Buffer.from(subTxt).toString('base64');
  fs.writeFileSync(subPath, encodedSub);
  console.log(`Subscription Base64 Generated. Access via http://<your-ip>:${PORT}/${SUB_PATH}`);
  
  // 仅在本地内存中托管订阅路由，不再向外发送
  app.get(`/${SUB_PATH}`, (req, res) => {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.send(encodedSub);
  });
}

// 主启动逻辑
async function startServer() {
  try {
    setupArgoConfig();
    await generateConfig();
    await downloadOfficialBinaries();

    // 启动 Xray
    if (fs.existsSync(webPath)) {
      await exec(`nohup ${webPath} -c ${FILE_PATH}/config.json >/dev/null 2>&1 &`);
      console.log('Xray core is running');
    }

    // 启动 Cloudflared
    if (fs.existsSync(botPath)) {
      let args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${ARGO_PORT}`;
      
      if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
      } else if (ARGO_AUTH.match(/TunnelSecret/)) {
        args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
      }

      await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
      console.log('Cloudflared tunnel is running');
      
      // 等待日志生成后提取域名
      setTimeout(extractDomains, 5000);
    }
  } catch (error) {
    console.error('Error starting services:', error.message);
  }
}

startServer();

// 网页根路由
app.get("/", (req, res) => {
  res.send(`Service is running safely. <br><br>Access /${SUB_PATH} to get your subscription list.`);
});

app.listen(PORT, () => console.log(`HTTP server listening on port ${PORT}`));
