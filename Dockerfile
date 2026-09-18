# Reference only: the TrueNAS deploy uses the stock Node image directly
# (see truenas-compose.yaml), so no registry push is needed.
FROM docker.io/library/node:22-alpine
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
ENV HOST=0.0.0.0 PORT=3030 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3030
CMD ["node", "server.js"]
