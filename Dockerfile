FROM python:3.13-alpine

ENV TZ=Europe/Paris

RUN apk add --no-cache tzdata curl \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && pip install --no-cache-dir requests pyyaml schedule

WORKDIR /app

COPY blocklist_scheduler.py .

ENTRYPOINT ["python3", "blocklist_scheduler.py"]
