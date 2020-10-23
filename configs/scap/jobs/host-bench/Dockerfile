# Note - container OS does *not* need to be the same as scanned host's OS. 
# FROM centos:centos8
FROM fedora:31

RUN yum install -y dnf-plugins-core
# This repo contains mongodb-org-tools (https://docs.mongodb.com/manual/tutorial/install-mongodb-on-red-hat/)
RUN dnf config-manager --add-repo https://repo.mongodb.org/yum/redhat/8/mongodb-org/4.4/x86_64/ --nogpgcheck

# Split --nogpgcheck install with the one with gpgcheck
RUN dnf install -y mongodb-org-tools --nogpgcheck
RUN dnf install -y \
    openscap-scanner \
    scap-security-guide \
    mongodb-org-tools \
    python3 \
    python3-pip \
    jq

ADD xccdfparser xccdfparser/

RUN cd xccdfparser && \
    pip3 install . && \
    cd -

# Prefetch remote resources for CentOS8: https://bugzilla.redhat.com/show_bug.cgi?id=1851375
# It actually uses redhat data.
RUN curl -o security-data-oval-com.redhat.rhsa-RHEL8.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml && \
    sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml#file:security-data-oval-com.redhat.rhsa-RHEL8.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml > ssg-rhel8-offline-ds.xml
# .. for CentOS7
RUN curl -o security-data-oval-com.redhat.rhsa-RHEL7.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml && \
    sed "s#https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml#file:security-data-oval-com.redhat.rhsa-RHEL7.xml#g" /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml > ssg-rhel7-offline-ds.xml

ADD tailoring-file-centos.xml tailoring/

ADD entrypoint.sh .

CMD ["./entrypoint.sh"]
