#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

mkdir -p media/qrcodes

# Run migrations
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser_if_none_exists

chmod +x build.sh