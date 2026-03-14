FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY provision.py .
COPY destroy.py .
COPY harden-phase1.sh .
COPY harden-phase2.sh .

RUN chmod +x harden-phase1.sh harden-phase2.sh

ENTRYPOINT ["python"]
CMD ["provision.py"]
