#!/usr/bin/env bash
origin_path=$(pwd)
work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)
cd $origin_path

### Primary variables
srv_home="/Users/$USER/srv"
project="pybase"

### Environment variables directed from primary ones
export src=$base_dir/../../../src
export config=$base_dir/../../..
export apphome=$srv_home/$project

echo src = "$src"
echo config = "$config"
echo apphome = "$apphome"


