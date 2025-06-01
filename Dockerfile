FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl tzdata && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests pyyaml schedule

ENV TZ=Europe/Paris

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

COPY blocklist_scheduler.py /app/blocklist_scheduler.py

RUN chmod +x /app/blocklist_scheduler.py

ENTRYPOINT ["python3", "/app/blocklist_scheduler.py"]
