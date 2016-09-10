#!/bin/bash

set -o errexit

sudo apt-get install libffi-dev python-pip
sudo pip install -r requirements.txt
