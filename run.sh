#!/bin/bash

OLDIFS=$IFS
IFS=$'\n'
firmwares=( $(find /data/firmware/images -type f -printf "'%p'\n") )
IFS=$OLDIFS

len=${#firmwares[@]}
stride=50
maxproc=20
c=0
for (( i=0; i<$len; i+=$stride ));
do
    c=$c+1
    sub=${firmwares[@]:$i:$stride}
    cmd="./walk.py ${sub[@]}"
    eval $cmd &
    if (( $c==$maxproc )); then
        wait
    fi
done
