FROM busybox:1.31.0-glibc

ADD dist/event-processor /
ADD configs/holmes/rules/_rules_list.yaml /configs/event-processor/holmes_rules.yaml

CMD ["/event-processor", "--rule", "/configs/event-processor/holmes_rules.yaml"]
