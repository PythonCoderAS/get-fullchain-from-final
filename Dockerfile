FROM python:3.13.0-alpine

WORKDIR /app
COPY ./requirements.txt /app/requirements.txt
RUN pip install --upgrade pip
RUN pip install -r /app/requirements.txt

COPY ./main.py /app/main.py

ENTRYPOINT ["python3", "/app/main.py"]
