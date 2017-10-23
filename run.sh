#!/bin/sh
echo 'running uwsgi: '
# uwsgi --socket 0.0.0.0:8000 -w wsgi
uwsgi --ini apisrv.ini
