#!/bin/bash
# FOR LOCAL USE ONLY
mysql.server start
./cloud_sql_proxy -instances=gotit-160017:us-central1:gotit=tcp:3306 \ -credential_file=~/gotit-c961c82b51c2.json &
