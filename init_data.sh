#!/bin/bash

echo "Initializing default notification events..."
python manage.py create_default_notification_events

echo "Initializing default metrics..."
python manage.py create_default_metrics

echo "Testing metric calculation..."
python manage.py calculate_metrics

echo "Initialization completed!" 