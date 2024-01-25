#!/bin/bash

# LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4 HEAPPROFILE=profile HEAP_PROFILE_TIME_INTERVAL=0 ./net-rule
# env LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4 HEAPPROFILE=agent HEAP_PROFILE_ALLOCATION_INTERVAL=1073741824 ./net-rule
# env HEAP_PROFILE_ALLOCATION_INTERVAL=10737418240
# env HEAP_PROFILE_INUSE_INTERVAL=104857600
# env HEAP_PROFILE_TIME_INTERVAL=1000 
# env LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4
# HEAPPROFILE=agent.prof ./net-rule
# env LD_PRELOAD=/lib/x86_64-linux-gnu/libtcmalloc.so.4 HEAPPROFILE=agent HEAP_PROFILE_TIME_INTERVAL=60 ./net-rule
./net-rule