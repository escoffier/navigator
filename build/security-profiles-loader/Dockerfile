ARG TAG=latest
ARG REPO=registry.t-appagile.com/tensorsecurity
FROM ${REPO}/baseimage-security-profiles-loader:${TAG}

ADD dist/security-profiles-loader /

CMD ["/security-profiles-loader"]
