FROM ubuntu:18.04
RUN apt update && apt -y install ca-certificates
COPY ranchercheck /ranchercheck
ENTRYPOINT ["/rancherheck"]
