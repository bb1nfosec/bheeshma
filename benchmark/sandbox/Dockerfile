# Disposable sandbox for detonating REAL npm malware samples against BHEESHMA.
#
# This image has no real secrets. Run it network-isolated (or behind a recording
# egress proxy) and throw it away after each run. See README.md in this folder.
#
#   docker build -t bheeshma-sandbox -f benchmark/sandbox/Dockerfile .
#   docker run --rm --network=none \
#     -e BHEESHMA_SANDBOX=1 \
#     -v "$PWD/benchmark/samples:/work/samples:ro" \
#     bheeshma-sandbox
#
# (Drop one package per subdirectory into benchmark/samples/ first. To observe
#  exfiltration attempts instead of blocking them, replace --network=none with a
#  --network pointing at a blackhole/recording proxy.)

FROM node:20-slim

# Non-root, throwaway user with a decoy HOME containing only decoy credentials.
RUN useradd -m -u 10001 detonator
WORKDIR /opt/bheeshma

# Copy only what's needed to run the suite (no node_modules — zero deps).
COPY src ./src
COPY benchmark ./benchmark
COPY package.json ./

# Decoy credentials so a sample that "steals" them gets only honey-tokens.
RUN printf '//registry.npmjs.org/:_authToken=DECOY_NOT_A_REAL_TOKEN\n' > /home/detonator/.npmrc \
 && printf 'API_KEY=DECOY\nAWS_SECRET_ACCESS_KEY=DECOY\n' > /home/detonator/.env \
 && mkdir -p /home/detonator/.ssh \
 && printf 'DECOY-PRIVATE-KEY\n' > /home/detonator/.ssh/id_rsa \
 && chown -R detonator:detonator /home/detonator /opt/bheeshma

USER detonator
ENV HOME=/home/detonator
WORKDIR /work

# Samples are mounted read-only at /work/samples.
CMD ["node", "/opt/bheeshma/benchmark/malware-suite.js", "/work/samples"]
