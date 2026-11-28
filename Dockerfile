FROM python:3.15.2-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS base

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
RUN pip install --no-cache-dir pytest==9.1.1 pytest-cov==7.1.0
COPY tests/ tests/
COPY pytest.ini .

FROM base AS lint
RUN pip install --no-cache-dir ruff==0.16.4
COPY ruff.toml .
COPY tests/ tests/
RUN ruff check . && ruff format --check .

FROM base
ENTRYPOINT ["./entrypoint.sh"]
