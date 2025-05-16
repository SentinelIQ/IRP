FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc python3-dev libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./

# Install UV if needed
RUN pip install --no-cache-dir uv

# Install dependencies with UV
RUN uv pip install -e .

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Create a non-root user
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Run entry point for migrations if needed
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Command to run the application
CMD ["gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000"]
