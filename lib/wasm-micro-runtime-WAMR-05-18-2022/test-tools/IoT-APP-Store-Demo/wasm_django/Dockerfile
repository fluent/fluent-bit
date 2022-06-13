FROM python:3.5

WORKDIR /app
ADD . /app

RUN pip install django

ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:80"]

