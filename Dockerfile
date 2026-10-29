FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    SWITCHYARD_DATA=/data \
    HOME=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip ca-certificates openssl spice-html5=0.3.0-2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# Pinned top-level dependency versions. npm transitive lock is not included in this release.
RUN npm install -g --no-audit --no-fund @bitwarden/cli@2026.10.0 \
    && npm install --prefix /opt/ui --no-save --no-audit --no-fund --ignore-scripts \
       @xterm/xterm@6.0.0 @xterm/addon-fit@0.11.0

# Official Apache Guacamole 1.6.0 browser runtime, retrieved at image build
# from Maven Central rather than using a repackaged third-party npm module.
# The artifact is not needed at runtime outside the finished image.
RUN python3 - <<'PYGUAC'
from urllib.request import urlopen
from zipfile import ZipFile
from io import BytesIO
from pathlib import Path
url = 'https://repo.maven.apache.org/maven2/org/apache/guacamole/guacamole-common-js/1.6.0/guacamole-common-js-1.6.0.zip'
with urlopen(url, timeout=30) as response:
    archive = response.read(10 * 1024 * 1024 + 1)
if len(archive) > 10 * 1024 * 1024:
    raise RuntimeError('Guacamole JS artifact exceeded size limit')
with ZipFile(BytesIO(archive)) as z:
    matches = [name for name in z.namelist() if name.endswith('/all.min.js') or name == 'all.min.js']
    if len(matches) != 1:
        raise RuntimeError('Unexpected Guacamole JS artifact layout')
    output = Path('/tmp/guacamole.js')
    output.write_bytes(z.read(matches[0]))
PYGUAC

COPY app/ /app/app/
COPY static/ /app/static/
# Distribution-provided, version-pinned LGPLv3 SPICE HTML5 client.
RUN set -eu; \
    mkdir -p /app/static/spice; \
    source_file="$(dpkg -L spice-html5 | grep '/main\.js

RUN cp /tmp/guacamole.js /app/static/guacamole.js \
    && cp /opt/ui/node_modules/@xterm/xterm/lib/xterm.js /app/static/xterm.js \
    && cp /opt/ui/node_modules/@xterm/xterm/css/xterm.css /app/static/xterm.css \
    && cp /opt/ui/node_modules/@xterm/addon-fit/lib/addon-fit.js /app/static/addon-fit.js \
    && groupadd --gid 10001 switchyard \
    && useradd --uid 10001 --gid switchyard --home-dir /data switchyard \
    && mkdir -p /data/keys \
    && chown -R 10001:10001 /data /app \
    && chmod 700 /data /data/keys

# Assert that every browser protocol dependency was packaged before release.
COPY scripts/verify-runtime-assets.sh /usr/local/bin/verify-runtime-assets
RUN bash /usr/local/bin/verify-runtime-assets /app/static

USER 10001:10001
EXPOSE 9791
HEALTHCHECK --interval=30s --timeout=4s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:9791/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9791", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
 | head -n 1)"; \
    css_file="$(dpkg -L spice-html5 | grep '/spice\.css

RUN cp /tmp/guacamole.js /app/static/guacamole.js \
    && cp /opt/ui/node_modules/@xterm/xterm/lib/xterm.js /app/static/xterm.js \
    && cp /opt/ui/node_modules/@xterm/xterm/css/xterm.css /app/static/xterm.css \
    && cp /opt/ui/node_modules/@xterm/addon-fit/lib/addon-fit.js /app/static/addon-fit.js \
    && groupadd --gid 10001 switchyard \
    && useradd --uid 10001 --gid switchyard --home-dir /data switchyard \
    && mkdir -p /data/keys \
    && chown -R 10001:10001 /data /app \
    && chmod 700 /data /data/keys

# Assert that every browser protocol dependency was packaged before release.
COPY scripts/verify-runtime-assets.sh /usr/local/bin/verify-runtime-assets
RUN bash /usr/local/bin/verify-runtime-assets /app/static

USER 10001:10001
EXPOSE 9791
HEALTHCHECK --interval=30s --timeout=4s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:9791/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9791", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
 | head -n 1)"; \
    if [ -z "$source_file" ] || [ -z "$css_file" ]; then \
        dpkg -L spice-html5; \
        echo 'SPICE HTML5 source files not found in installed package' >&2; \
        exit 1; \
    fi; \
    cp -a "$(dirname "$source_file")/." /app/static/spice/; \
    cp "$css_file" /app/static/spice/spice.css

RUN cp /tmp/guacamole.js /app/static/guacamole.js \
    && cp /opt/ui/node_modules/@xterm/xterm/lib/xterm.js /app/static/xterm.js \
    && cp /opt/ui/node_modules/@xterm/xterm/css/xterm.css /app/static/xterm.css \
    && cp /opt/ui/node_modules/@xterm/addon-fit/lib/addon-fit.js /app/static/addon-fit.js \
    && groupadd --gid 10001 switchyard \
    && useradd --uid 10001 --gid switchyard --home-dir /data switchyard \
    && mkdir -p /data/keys \
    && chown -R 10001:10001 /data /app \
    && chmod 700 /data /data/keys

# Assert that every browser protocol dependency was packaged before release.
COPY scripts/verify-runtime-assets.sh /usr/local/bin/verify-runtime-assets
RUN bash /usr/local/bin/verify-runtime-assets /app/static

USER 10001:10001
EXPOSE 9791
HEALTHCHECK --interval=30s --timeout=4s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:9791/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9791", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
