FROM node:20-slim

WORKDIR /tmp

COPY index.js index.html package.json ./

EXPOSE 3000/tcp

# 换用标准 Debian 系统的包管理器 apt-get 安装必需环境
RUN apt-get update && apt-get upgrade -y &&\
    apt-get install -y --no-install-recommends openssl curl iproute2 coreutils unzip ca-certificates wget bash &&\
    chmod +x index.js &&\
    npm install

CMD ["node", "index.js"]
