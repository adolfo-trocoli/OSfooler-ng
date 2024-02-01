dir=$(/usr/bin/dirname $0)

script=${dir}/../osfooler_ng/osfooler_ng.py
. ${dir}/../../bubble/bin/activate 
python3 ${script} \
  -m "__OS_NAME" -o "__OSGENRE" -d "__DETAILS_P0F" > ${dir}/service.log 2>&1 
