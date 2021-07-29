#!/bin/bash

service apache2 start
su -c redis-server redis
