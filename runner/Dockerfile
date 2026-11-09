FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends firefox-esr xvfb xauth xdotool imagemagick fonts-dejavu-core python3 libnss3-tools mitmproxy iptables ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 12001 --create-home browser
WORKDIR /runner
COPY . /runner
ENV PYTHONUNBUFFERED=1 DISPLAY=:99
CMD ["python3", "/runner/server.py"]
