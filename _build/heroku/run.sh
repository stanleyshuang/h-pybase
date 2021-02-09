#!/usr/bin/env bash

### 1. Update config code
echo "cp -a $config/. $apphome/"
      cp -a $config/. $apphome/

if [ -d "$env/config" ]; then
  echo "cp -a $env/config/. $apphome/"
        cp -a $env/config/. $apphome/
fi

### 2. Check-in Heroku
echo "-- Run the following script ----"
echo "cd $apphome/"
echo "git add ."
echo "git commit -m \"$1\""
echo "git push heroku master"
