# ─── Stage: production ───────────────────────────────────────
FROM python:3.11-slim AS prod

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY provision.py destroy.py harden-phase1.sh harden-phase2.sh verify.sh .
RUN chmod +x harden-phase1.sh harden-phase2.sh verify.sh

ENTRYPOINT ["python"]
CMD ["provision.py"]


# ─── Stage: test ─────────────────────────────────────────────
# Extends prod so tests run against the exact same dependencies.
# All test tooling stays inside the image — nothing installed on the host.
#
# Build:  podman build --target test -t cloud-vm-provisioner-test .
# Run:    podman run --rm cloud-vm-provisioner-test
FROM prod AS test

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY tests/ tests/

ENTRYPOINT ["pytest"]
CMD ["tests/", \
     "--cov=.", "--cov-report=term-missing", \
     "--cov-fail-under=60", \
     "-v", "--tb=short"]
