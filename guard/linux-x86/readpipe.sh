#!/bin/bash

LEDPIPE="/tmp/ledfifo"
MSGPIPE="/tmp/msgfifo"

[ ! -p $LEDPIPE ] && mkfifo $LEDPIPE
[ ! -p $MSGPIPE ] && mkfifo $MSGPIPE

while true;
do
    read -t 0.2 line <> $LEDPIPE
    echo "read led msg: ------------------------ $line"
    sleep 0.5
done
    
