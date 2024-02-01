#!/bin/bash

dir=$(/usr/bin/dirname $0)

/bin/nohup ${dir}/OSfooler-ng/service/wrapper.sh &
echo $! > ${dir}/service.pid
