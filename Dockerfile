FROM python:3.14.7-alpine AS base

ENV TZ=Europe/Paris

RUN apk add --no-cache tzdata curl su-exec \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY blocklist_scheduler.py entrypoint.sh VERSION ./
RUN chmod +x entrypoint.sh

FROM base AS test
RUN pip install --no-cache-dir pytest==9.1.1
COPY tests/ tests/
COPY pytest.ini .

FROM base
ENTRYPOINT ["./entrypoint.sh"]
