#!/bin/bash

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate

# Create all default data
echo "Creating default data..."
python manage.py shell -c "from api.admin import create_default_data; create_default_data()"

# Execute the command passed to the container
exec "$@" 