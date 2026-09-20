FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies
COPY examples ./examples

RUN pip install --no-cache-dir .

EXPOSE 8080 8443
CMD ["aetherwall", "up", "--plane", "both", "--host", "0.0.0.0"]
