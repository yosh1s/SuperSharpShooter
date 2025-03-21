from python:3.8-slim

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt
ENTRYPOINT ["python3", "SuperSharpShooter.py"]
