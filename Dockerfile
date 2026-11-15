# Stage 1: test
FROM python:3.12-slim AS test
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY project.py test_project.py ./
RUN pytest test_project.py

# Stage 2: final image
FROM python:3.12-slim
WORKDIR /app
COPY --from=test /app/project.py ./
RUN useradd --create-home appuser
USER appuser
ENTRYPOINT ["python", "project.py"]
