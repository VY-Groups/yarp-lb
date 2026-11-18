FROM python:3.14.10-alpine3.24
WORKDIR /app
COPY --chown=65532:65532 receiver.py /app/receiver.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "-I", "/app/receiver.py"]

