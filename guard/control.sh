#!/bin/sh

if [ "$1" = "1" ];
then
    echo $2 $3
elif [ "$1" = "0" ];
then
    echo -n "00:0A:0B:0C:0D:0E"
fi
