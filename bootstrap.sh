#!/bin/bash

dir=$(/usr/bin/dirname $0)

cd ${dir}
dir=$PWD)

python3 -m venv bubble
. bubble/bin/activate
python3 -m pip install -r ${dir}/requirements.txt

chmod -R 500 ${dir}
chown -R root:root ${dir}
cd ${dir}/service
