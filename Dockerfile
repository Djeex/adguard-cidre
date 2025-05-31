FROM alpine:latest

RUN apk add --no-cache curl bash busybox-cron tzdata

COPY update-blocklist.sh /usr/local/bin/update-blocklist.sh
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/update-blocklist.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
