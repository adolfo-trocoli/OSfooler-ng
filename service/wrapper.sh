dir=$(/usr/bin/dirname $0)

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 3 ]; then
  exit 1
fi

script=${dir}/../osfooler_ng/osfooler_ng.py
. ${dir}/../../bubble/bin/activate 
${dir}/../../bubble/bin/python3 ${script} -m ${1} -o ${2} -d ${3} > ${dir}/service.log 2>&1 
