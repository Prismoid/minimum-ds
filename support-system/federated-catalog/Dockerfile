FROM python:3.13-slim

WORKDIR /app

# 依存パッケージのインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリ本体
COPY ./app /app

EXPOSE 61000

# FastAPI 起動
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "61000"]