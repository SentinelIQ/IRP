#!/bin/bash

# Apply migrations
python manage.py migrate

# Execute initialization to create default data
python manage.py shell -c "from api.admin import create_default_data; create_default_data()"

echo "Initialization complete!" 