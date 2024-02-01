#!/bin/bash
dir=$(/usr/bin/dirname $0)
pkill -9 $(cat ${dir}/service.pid)
