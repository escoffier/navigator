FROM busybox

ADD configs/drift-prevention/ld-preload /drift-prevention
ADD dist/file-checker /drift-prevention/

CMD ["tail", "-f", "/dev/null"]
