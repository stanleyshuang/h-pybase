#!/usr/bin/env bash
base_dir=$(dirname "$0")
repo="$base_dir/.."
env="$base_dir/_build/$1"

### 1. Make the file structure
### 2. Create Python3 virtual environment

### 0. Check arguments
# the configuration
if [ $# != 1 ]; then
    echo "!> Missing environment information." 
    echo "!> Usage: $0 <lab | stg | pro>"
    exit
fi

# environment variables
if [ ! $apphome ]; then
  echo '!> Missing $apphome.' 
  echo "!> Run 'source $env/env.sh'"
  exit
fi

### 1. Make the file structure
# file structure
# $repo
#  |-- install ($base_dir)
#         |-- _build
#         |      |-- $env
#         |            |-- app: app home
#         |            |-- data: the data
#         |            |-- env.sh
#         |-- app: app home
#         |-- data: the data 
#         |-- docker-imgs: docker images
#         |-- install.sh

# $apphome: copy from $repo/app + $env/app
#  |-- $data: copy from $repo/data + $env/data

if [[ ! -d $apphome ]]; then
  echo "mkdir -p $apphome"
        mkdir -p $apphome
fi

if [[ ! -d $apphome/data ]]; then
  echo "mkdir -p $apphome/data"
        mkdir -p $apphome/data
fi

# update latest source code
echo "cp -a $repo/app/. $apphome/"
      cp -a $repo/app/. $apphome/

if [ -d "$env/app" ]; then
  echo "cp -a $env/app/. $apphome/"
        cp -a $env/app/. $apphome/
fi

### update data folder
echo "cp -a $repo/data/. $apphome/data/"
      cp -a $repo/data/. $apphome/data/

if [ -d "$env/data" ]; then
  echo "cp -a $env/data/. $apphome/data/"
        cp -a $env/data/. $apphome/data/
fi


### 2. Create Python3 virtual environment
if ! [ -d "$apphome/venv" ]; then
  echo "python3 -m venv $apphome/venv"
        python3 -m venv $apphome/venv
  echo "source $apphome/venv/bin/activate"
        source $apphome/venv/bin/activate
  echo "pip install -r $repo/install/docker-imgs/requirements.txt"
        pip install -r $repo/install/docker-imgs/requirements.txt
  echo "deactivate"
        deactivate
fi

### Run script
echo "-- Run the following script ----"
echo "cd $apphome/"
echo "source $apphome/venv/bin/activate"
