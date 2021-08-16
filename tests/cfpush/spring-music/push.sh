#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cf push $1 -p ${DIR}/build/libs/spring-music-1.0.jar --random-route
