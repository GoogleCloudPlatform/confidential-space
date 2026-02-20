# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the Python script into the container at /app
COPY src/test_workload.py .

# Command to run the Python script when the container launches
CMD ["python", "./test_workload.py"]