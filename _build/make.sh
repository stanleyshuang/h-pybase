#!/usr/bin/env bash

### 0. Check arguments
# the configuration
if [ $# == 0 ]; then
  echo "!> Missing the argument(s)." 
  echo "!> Usage: $0 <mac-lab | heroku [commit message]>"
  exit
elif [ $1 != 'mac-lab' ] && [ $1 != 'heroku' ]; then
  echo "!> The value of argument 1 is error." 
  echo "!> Usage: $0 <mac-lab | heroku [commit message]>"
  exit
fi

work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)

repo="$base_dir/.."
env="$repo/_build/$1"

# environment variables
export src=$repo/src
export config=$repo/config
export apphome=$srv_home/$project
export appstatic=$srv_home/$project/static
export appdownloads=$srv_home/$project/downloads

if [ ! $src ] || [ ! $config ] || [ ! $apphome ]; then
  echo '!> Missing $src.' 
  echo "!> Run 'source $env/env.sh'"
  exit
fi

echo src = "$src"
echo config = "$config"
echo apphome = "$apphome"

### 1. Make the file structure
# file structure
# $repo
#   |-- _build
#          |-- $env 
#          |     |-- src: customized app home
#          |     |-- config: customized configuration
#          |     |-- env.sh
#          |     |-- run.sh
#          |
#          |-- make.sh
#
# $src: common app home
# $static: external static data
#
# $config: requirement.txt, docker images, and so on
#
# $apphome: copy from $src + $env/src
# $appstatic: copy from $static
# $appdownloads: copy from $static

if [ ! -d $apphome ]; then
  echo "mkdir -p $apphome"
        mkdir -p $apphome
fi

# update latest source code
echo "cp -a $src/. $apphome/"
      cp -a $src/. $apphome/

if [ -d "$env/src" ]; then
  echo "cp -a $env/src/. $apphome/"
        cp -a $env/src/. $apphome/
fi

# update latest configuration
echo "cp -a $config/. $apphome/"
      cp -a $config/. $apphome/

if [ -d "$env/config" ]; then
  echo "cp -a $env/config/. $apphome/"
        cp -a $env/config/. $apphome/
fi

# copy external static data
if [ -d "$static" ]; then
  if [ ! -d $appstatic ]; then
    echo "mkdir -p $appstatic"
          mkdir -p $appstatic
  fi
  echo "cp -a $static/. $appstatic/"
        cp -a $static/. $appstatic/
fi

if [ ! -d $appdownloads ]; then
  echo "mkdir -p $appdownloads"
        mkdir -p $appdownloads
  echo "chmod 777 $appdownloads"
        chmod 777 $appdownloads
fi


### 2. Run script
if [ -f "$env/run.sh" ]; then
  echo "repo=\"$repo\" env=\"$env\" $env/run.sh  $2"
        repo="$repo"   env="$env"   $env/run.sh "$2"
fi
