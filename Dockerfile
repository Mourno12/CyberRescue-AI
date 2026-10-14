# Single image, multiple commands. Each agent is just a different module
# under `python -m agents.<name>.main` selected via docker-compose CMD.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# uv: fast installer; pre-installed so `uv pip install` works without network
# hiccups during builds.
RUN pip install --no-cache-dir uv

# Copy metadata AND source before the editable install: pyproject declares
# readme = "README.md" (install fails if absent) and the setuptools package
# finder must see shared/ + agents/ to register them for editable import.
COPY pyproject.toml README.md ./
COPY shared/ ./shared/
COPY agents/ ./agents/
COPY injector/ ./injector/
COPY exporter/ ./exporter/
# CyberRescue AI extension: the Core the Commander's action gate consults.
COPY cyberrescue/ ./cyberrescue/

RUN uv pip install --system -e . --no-cache

# Compose overrides this per service. Default is a no-op so the image fails
# loudly if launched without a service.
CMD ["python", "-c", "import sys; print('set a service command in docker-compose.yml'); sys.exit(2)"]
