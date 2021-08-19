#!/bin/bash

/usr/local/apache-tomcat-8.5.70/bin/startup.sh
su -c redis-server redis
