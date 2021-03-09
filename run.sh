#! /bin/bash

# Usage: cd <Project_ROOT> && ./run.sh
DIR=`pwd`

mkdir -p logs
. $DIR/env.sh
/usr/local/openresty/bin/openresty -p . -c "$DIR/conf/nginx.conf" -g "daemon off; error_log /dev/stdout warn;"
