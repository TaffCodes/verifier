#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

mkdir -p media/qrcodes

# Run migrations
python manage.py migrate


chmod +x build.sh