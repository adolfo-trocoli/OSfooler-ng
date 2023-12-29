#!/bin/bash

dir=$(/usr/bin/dirname $0)

script=${dir}/OSfooler-ng/osfooler_ng/osfooler_ng.py
/usr/bin/nohup /usr/bin/python3 ${script} \
  -m "__OS_NAME" -o "__OSGENRE" -d "DETAILS_P0F" > ${dir}/service.log 2>&1 &
echo $! > ${dir}/service.pid
