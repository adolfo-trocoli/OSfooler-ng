#!/bin/bash
dir=$(/usr/bin/dirname $0)
parent=$(cat ${dir}/service.pid)
child=$(ps -o pid --no-headers --ppid  ${parent} | tr -d '[:blank:\n]')
grandchildren=$(ps -o pid --no-headers --ppid  ${child} | tr -d '[:blank:\n]')
kill -9 ${grandchildren} ${child}
