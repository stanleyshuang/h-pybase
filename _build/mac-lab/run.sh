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
echo "export FLASK_APP=flask_app.py"
echo "flask run"
