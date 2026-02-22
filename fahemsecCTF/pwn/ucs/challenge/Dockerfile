FROM debian:12-slim

# Install socat for network service
RUN apt-get update && apt-get install -y --no-install-recommends socat \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 ctf
WORKDIR /home/ctf

# Copy binary files only (no source code or exploit)
COPY app ./
COPY libvuln.so ./
COPY ld-linux-x86-64.so.2 ./
COPY libc.so.6 ./
COPY flag ./

# Make binaries executable
RUN chmod +x ./app ./ld-linux-x86-64.so.2 ./libc.so.6 ./libvuln.so

# Secure the flag
RUN chown root:root ./flag && chmod 444 ./flag

EXPOSE 1234
USER ctf

# Run the challenge with custom ld and libc
CMD sh -c 'socat -dd TCP-LISTEN:1234,reuseaddr,fork EXEC:"/home/ctf/app",stderr'