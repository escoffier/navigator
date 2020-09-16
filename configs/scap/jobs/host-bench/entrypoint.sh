#!/bin/bash

# Source host's OS information
source /mnt/root/etc/os-release

# Examples:
# NAME="Ubuntu Core"
# VERSION_ID="16"
#
# NAME=Fedora
# VERSION_ID=31
#
# NAME="CentOS Linux"
# VERSION_ID="8"

case $NAME in 
  *Ubuntu*)
    DS_STR="ubuntu${VERSION_ID}04"
  ;;
  *CentOS*)
    DS_STR="centos${VERSION_ID}"
  ;;
  *)
    echo "Unsupported OS: $NAME"
    exit 1
  ;;
esac

DSPATH="/usr/share/xml/scap/ssg/content/ssg-$DS_STR-ds.xml"
PROFILE="content_profile_standard"

echo "Using datasource $DSPATH"
echo "Using profile $PROFILE"

oscap-chroot /mnt/root/ xccdf eval --report=report.html --results=results.html --profile=content_profile_standard $DSPATH
exit $?

# TODO: write to mongo