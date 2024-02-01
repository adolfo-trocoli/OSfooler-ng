#!/bin/bash
dir=$(/usr/bin/dirname $0)
parent=$(cat ${dir}/service.pid)
child=$(ps -o pid --no-headers --ppid  ${parent})
grandchildren=$(ps -o pid --no-headers --ppid  ${child})
kill -9 ${grandchildren} ${child}
