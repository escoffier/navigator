FROM fedora:31

RUN dnf -y install openscap-scanner scap-security-guide

ADD entrypoint.sh .

CMD ["./entrypoint.sh"]