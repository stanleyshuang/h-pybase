#!/usr/bin/env bash
base_dir=$(dirname "$0")

### Primary variables
srv_home="/Users/$USER/srv"
project="pybase"

### Environment variables directed from primary ones
export apphome=$srv_home/$project