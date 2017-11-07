#!/bin/bash
for i in `ps -efw | grep -i flask | grep -v grep | awk '{ print $2 }'`
do
  kill -9 $i
done
