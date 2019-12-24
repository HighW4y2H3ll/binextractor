#!/bin/bash

killall /usr/bin/python3
mount|grep _tmpx|awk '{ print $3 }'|xargs sudo umount
sudo rm -rf /tmp/*_tmpx
sudo rm -rf /tmp/*_binx
sudo rm -rf ./*_tmpx
sudo rm -rf ./*_binx
