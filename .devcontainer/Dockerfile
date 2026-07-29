FROM rust:latest

# At the moment, tshark 4.6.1 is not available in debian stable.
COPY debian-forky.sources /etc/apt/sources.list.d
RUN apt-get update && apt-get install -y libwireshark-dev tshark