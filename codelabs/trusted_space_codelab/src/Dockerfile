FROM tensorflow/tensorflow:latest-gpu-jupyter

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --ignore-installed -r requirements.txt

COPY inference_server.py .

EXPOSE 8080

ENTRYPOINT ["python", "inference_server.py"]