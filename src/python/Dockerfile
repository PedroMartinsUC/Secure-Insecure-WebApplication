#
# Authors: Nuno Antunes <nmsa@dei.uc.pt>, João Antunes <jcfa@dei.uc.pt>
#

FROM python:3.11-alpine

RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev

RUN pip install flask==2.2.2

RUN pip install psycopg2-binary

RUN pip install pyotp

RUN pip install password_strength

COPY . /app

VOLUME ["/app"]

WORKDIR /app

RUN mkdir -p logs

EXPOSE 5000

CMD ["python", "app.py"]
