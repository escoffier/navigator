# Note - container OS does *not* need to be the same as scanned host's OS. 
FROM registry.t-appagile.com/tensorsecurity/baseimage-scanner:latest

ADD xccdfparser xccdfparser/

RUN cd xccdfparser \
    && pip3 install . \
    && cd - \

# Prefetch remote resources for CentOS8: https://bugzilla.redhat.com/show_bug.cgi?id=1851375
# It actually uses redhat data.
    && curl -o security-data-oval-com.redhat.rhsa-RHEL8.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml \
    && sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml#file:security-data-oval-com.redhat.rhsa-RHEL8.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml > ssg-rhel8-offline-ds.xml \
# .. for CentOS7
    && curl -o security-data-oval-com.redhat.rhsa-RHEL7.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml \
    && sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml#file:security-data-oval-com.redhat.rhsa-RHEL7.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml > ssg-rhel7-offline-ds.xml

ADD tailoring-file-centos.xml tailoring/

ADD entrypoint.sh .

ADD add_translations.py .
ADD translations.json .

CMD ["./entrypoint.sh"]
