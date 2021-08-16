#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
mv data.file ${DIR}/linux-compiled/
cf push $1 -p ${DIR}/linux-compiled --random-route
