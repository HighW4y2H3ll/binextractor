#!/bin/bash

OLDIFS=$IFS
IFS=$'\n'
firmwares=( $(find /data/firmware/images -type f -printf "'%p'\n"|shuf) )
IFS=$OLDIFS

len=${#firmwares[@]}
stride=50
maxproc=20
c=0
for (( i=0; i<$len; i+=$stride ));
do
    c=$c+1
    sub=${firmwares[@]:$i:$stride}
    cmd="timeout 2h ./walk.py ${sub[@]}"
    eval $cmd &
    if (( $c==$maxproc )); then
        wait
        c=0
    fi
done
