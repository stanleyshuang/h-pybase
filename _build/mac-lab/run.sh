#!/usr/bin/env bash

### 1. Create Python3 virtual environment
if ! [ -d "$apphome/venv" ]; then
  echo "python3 -m venv $apphome/venv"
        python3 -m venv $apphome/venv
  echo "source $apphome/venv/bin/activate"
        source $apphome/venv/bin/activate
  if [ -f "$config/requirements.txt" ]; then
    echo "pip install -r $config/requirements.txt"
          pip install -r $config/requirements.txt
  fi
  if [ -f "$env/config/requirements.txt" ]; then
    echo "pip install -r $env/config/requirements.txt"
          pip install -r $env/config/requirements.txt
  fi

  echo "deactivate"
        deactivate
fi

### 2. Run app script
echo "-- Run the following script ----"
echo "cd $apphome/"
echo "source $apphome/venv/bin/activate"
# Veu environment
if ! [ -d "$apphome/client" ]; then
  echo "cd $apphome"
  echo "vue create client"
else
  echo "cd $apphome/client"
  echo "npm install"
fi
echo "cd $apphome"
echo "npm run build"
echo "npm start"
