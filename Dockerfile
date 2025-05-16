FROM python:3.11-slim

WORKDIR /app

# Instala o uv
RUN pip install --upgrade pip && pip install uv

# Copia arquivos necessários para instalar dependências
COPY pyproject.toml README.md ./

# Define o modo de linkagem e PATH
ENV UV_LINK_MODE=copy
ENV PATH="/app/.venv/bin:$PATH"

# Cria o ambiente virtual antes de instalar dependências
RUN uv venv .venv

# Copia o restante do código
COPY . .

# Instala as dependências
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -e .

# Define variáveis do Django
ENV DJANGO_SETTINGS_MODULE=core.settings
ENV PYTHONUNBUFFERED=1

# Coleta arquivos estáticos
RUN mkdir -p staticfiles && python manage.py collectstatic --noinput

# Executa o projeto com gunicorn
CMD ["gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000"]
