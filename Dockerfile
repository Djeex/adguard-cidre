FROM python:3.13-alpine AS base

ENV TZ=Europe/Paris

RUN apk add --no-cache tzdata curl \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && pip install --no-cache-dir requests pyyaml schedule

WORKDIR /app

COPY blocklist_scheduler.py .

FROM base AS test
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY tests/ tests/
COPY pytest.ini .

FROM base
ENTRYPOINT ["python3", "blocklist_scheduler.py"]
