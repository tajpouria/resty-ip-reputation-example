#! /bin/bash

# Usage: cd <Project_ROOT> && .dev/run.sh
DIR=`pwd`

mkdir -p logs &&\
/usr/local/openresty/bin/openresty -p . -c "$DIR/conf/nginx.conf" -g "daemon off; error_log /dev/stdout warn;"
