# Throwaway sandbox to run the Semgate enforce loop safely.
# It executes real commands, so it is built to be contained: non-root user,
# no bind mount of the host, a scratch workspace created inside the container.
FROM python:3.12-slim

# curl is present in the example tasks; keep the image small otherwise.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Semgate and its Jev client. requirements installed first for layer caching.
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY semgate /app/semgate
COPY policies /app/policies
RUN pip install --no-cache-dir python-dotenv typesafe-sdk pyyaml

# Sandbox config, grant, loop, and tasks.
COPY sandbox/semgate.enforce.json /sandbox/semgate.enforce.json
COPY sandbox/semgate.yolo.json /sandbox/semgate.yolo.json
COPY sandbox/grant.json /sandbox/grant.json
COPY sandbox/run_loop.py /sandbox/run_loop.py
COPY sandbox/tasks.example.jsonl /sandbox/tasks.jsonl

# Run as a non-root user with a writable sandbox and scratch workspace only.
RUN useradd -m runner \
    && mkdir -p /sandbox/state /sandbox/workspace \
    && chown -R runner:runner /sandbox
USER runner

# TYPESAFE_API_KEY is passed at run time, never baked into the image.
ENTRYPOINT ["python3", "/sandbox/run_loop.py"]
