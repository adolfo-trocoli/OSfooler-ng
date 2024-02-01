#!/bin/bash

dir=$(/usr/bin/dirname $0)
/bin/nohup ${dir}/wrapper.sh /dev/null &
echo $! > ${dir}/service.pid
