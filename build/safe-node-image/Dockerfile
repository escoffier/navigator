FROM docker

WORKDIR /app

COPY ./dist/safe-node-image /app
RUN chmod u+x safe-node-image

ENV GIN_MODE=release


ENTRYPOINT ["./safe-node-image"]
