FROM rust:1.69

RUN mkdir -p /home/webapp
WORKDIR /home/webapp
COPY . /home/webapp

RUN cargo build --release

CMD ./target/release/rust
