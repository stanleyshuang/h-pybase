#!/usr/bin/env bash

### 0. Initialize .git
if [ ! -d $apphome/.git ]; then
  work_path=$(dirname $0)
  cd $work_path
  base_dir=$(pwd)

  echo "cd $apphome"
        cd $apphome

  echo "git init"
        git init

  echo "heroku git:remote -a $project"
        heroku git:remote -a $project

  echo "heroku buildpacks:add --index 1 heroku/nodejs"
        heroku buildpacks:add --index 1 heroku/nodejs

  echo "heroku buildpacks:add --index 2 heroku/python"
        heroku buildpacks:add --index 2 heroku/python

  # Veu environment
  echo "vue create client"
        vue create client

  # pop up
  cd $base_dir
fi

### 2. Check-in Heroku
echo "-- Run the following script ----"
# Veu environment
if ! [ -d "$apphome/client" ]; then
  echo "cd $apphome"
  echo "vue create client"
else
  echo "cd $apphome/client"
  echo "npm install"
fi
echo "cd $apphome"
echo "git add ."
echo "git commit -m \"$1\""
echo "git push heroku master"
