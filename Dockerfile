FROM node:alpine3.22

WORKDIR /tmp

COPY index.js index.html package.json ./

EXPOSE 3000/tcp

# 【安全修复】补充了 Xray 安装必备的 unzip 包，以及用于安全下载的 ca-certificates 证书包
RUN apk update && apk upgrade &&\
    apk add --no-cache openssl curl gcompat iproute2 coreutils unzip ca-certificates &&\
    apk add --no-cache bash &&\
    chmod +x index.js &&\
    npm install

CMD ["node", "index.js"]
