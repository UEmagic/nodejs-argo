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
// 【安全修复】如果未设置订阅路径，生成32位随机安全字符串防止全网扫描器白嫖
const SUB_PATH = process.env.SUB_PATH || crypto.randomBytes(16).toString('hex');
// 【安全修复】强制转换端口为数字，防止环境变量注入攻击
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || 3000, 10);
const ARGO_PORT = parseInt(process.env.ARGO_PORT || 8001, 10);
const UUID = process.env.UUID || '448ecbf7-b396-4df5-86c1-5139589b668f'; 
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';
const ARGO_AUTH = process.env.ARGO_AUTH || '';
const CFIP = process.env.CFIP || 'www.visa.com.sg';
const CFPORT = process.env.CFPORT || 443;
const NAME = process.env.NAME || 'SafeNode';

const webPath = path.join(FILE_PATH, 'web');
const botPath = path.join(FILE_PATH, 'bot');
const subPath = path.join(FILE_PATH, 'sub.txt');
const bootLogPath = path.join(FILE_PATH, 'boot.log');

// 初始化运行目录
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} created`);
}

// 【安全修复】启动后台进程的安全函数 (取代容易产生注入的 exec + nohup)
function spawnProcess(command, args) {
  const child = spawn(command, args, {
    detached: true,
    stdio: 'ignore'
  });
  child.unref();
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
    outbounds: [ 
      { protocol: "freedom", tag: "direct" }, 
      { protocol: "blackhole", tag: "block" } 
    ],
    // 【安全修复】添加 SSRF 防护路由，屏蔽所有局域网/云元数据 IP 的代理请求
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        {
          type: "field",
          ip: [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10"
          ],
          outboundTag: "block"
        }
      ]
    }
  };
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

// 判断架构并从官方渠道下载二进制文件
async function downloadOfficialBinaries() {
  const arch = os.arch();
  const isArm = (arch === 'arm' || arch === 'arm64' || arch === 'aarch64');
  const xrayArch = isArm ? 'arm64-v8a' : '64';
  const cfArch = isArm ? 'arm64' : 'amd64';

  if (!fs.existsSync(botPath)) {
    console.log("Downloading official Cloudflared...");
    try {
      await exec(`wget -qO ${botPath} https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cfArch}`);
      await exec(`chmod 775 ${botPath}`);
    } catch (e) {
      console.error("Cloudflared download failed.", e.message);
    }
  }

  if (!fs.existsSync(webPath)) {
    console.log("Downloading official Xray-core...");
    try {
      await exec(`wget -qO- https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xrayArch}.zip | unzip -qd ${FILE_PATH} -`);
      await exec(`mv ${FILE_PATH}/xray ${webPath}`);
      await exec(`chmod 775 ${webPath}`);
      await exec(`rm -f ${FILE_PATH}/geoip.dat ${FILE_PATH}/geosite.dat ${FILE_PATH}/LICENSE ${FILE_PATH}/README.md`);
    } catch (e) {
      console.error("Xray download failed.", e.message);
    }
  }
}

// 配置固定隧道 Json
function setupArgoConfig() {
  if (ARGO_AUTH.includes('TunnelSecret')) {
    try {
      // 【安全修复】标准的 JSON 解析，避免切片越界导致的程序崩溃
      const authData = JSON.parse(ARGO_AUTH);
      const secret = authData.TunnelSecret;
      
      fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
      const tunnelYaml = `
tunnel: ${secret}
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
    } catch (err) {
      console.error("Failed to parse ARGO_AUTH JSON:", err.message);
    }
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
    } catch (error) {}
  }

  if (argoDomain) {
    console.log('ArgoDomain successfully fetched:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    setTimeout(extractDomains, 5000);
  }
}

// 生成节点链接
async function generateLinks(argoDomain) {
  // 【隐私修复】废弃通过 api.ip.sb 获取公网 IP (防止被第三方 API 记录跟踪)
  const nodeName = `${NAME}-Node`;
  
  const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'};
  
  const subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
`;

  const encodedSub = Buffer.from(subTxt).toString('base64');
  fs.writeFileSync(subPath, encodedSub);
  
  // 在控制台打印生成的安全订阅路径
  console.log(`====================================================`);
  console.log(`[WARNING] Your Subscription path is securely set to:`);
  console.log(`http://<your-ip>:${PORT}/${SUB_PATH}`);
  console.log(`====================================================`);
  
  // 订阅接口路由
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
      spawnProcess(webPath, ['-c', path.join(FILE_PATH, 'config.json')]);
      console.log('Xray core is running');
    }

    // 启动 Cloudflared (使用安全的数组参数防止命令注入)
    if (fs.existsSync(botPath)) {
      let args = [];
      if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH];
      } else if (ARGO_AUTH.includes('TunnelSecret')) {
        args = ['tunnel', '--edge-ip-version', 'auto', '--config', path.join(FILE_PATH, 'tunnel.yml'), 'run'];
      } else {
        args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', '--logfile', bootLogPath, '--loglevel', 'info', '--url', `http://localhost:${ARGO_PORT}`];
      }
      
      spawnProcess(botPath, args);
      console.log('Cloudflared tunnel is running');
      setTimeout(extractDomains, 5000);
    }
  } catch (error) {
    console.error('Error starting services:', error.message);
  }
}

startServer();

// ================= 路由逻辑 =================

// 【完美伪装修复】根路由读取并返回 index.html 伪装成正规SaaS站点，躲避审查和扫描器
app.get("/", (req, res) => {
  const htmlPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    // 降级处理，如果没找到 index.html
    res.send("Welcome to CodeFlow API Server.");
  }
});

// 监听端口
app.listen(PORT, () => console.log(`HTTP server listening on port ${PORT}`));
