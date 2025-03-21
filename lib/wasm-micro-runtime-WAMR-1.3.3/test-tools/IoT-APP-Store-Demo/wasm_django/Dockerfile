FROM python:3.5

WORKDIR /app
COPY . /app

# hadolint ignore=DL3013
RUN pip install django --no-cache-dir

ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:80"]
