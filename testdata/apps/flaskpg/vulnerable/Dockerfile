FROM docker.io/library/python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt ./
COPY wheels ./wheels
RUN pip install --no-index --find-links=/app/wheels --require-hashes -r requirements.txt
COPY . .
RUN mkdir -p /app/uploads
EXPOSE 8000
CMD ["python", "app.py"]
