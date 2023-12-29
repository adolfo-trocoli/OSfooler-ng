#!/bin/bash
dir=$(/usr/bin/dirname $0)
kill -9 $(cat ${dir}/service.pid)
