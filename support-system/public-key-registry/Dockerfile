FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app

EXPOSE 60000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "60000"]
