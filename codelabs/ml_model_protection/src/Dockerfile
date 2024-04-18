# Use a base image with Python and TensorFlow pre-installed
FROM tensorflow/tensorflow:2.13.0
# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY inference_server.py /app/

# Set the custom label "tee.launch_policy.allow_cmd_override" to "true"
LABEL "tee.launch_policy.allow_cmd_override"="true"

# Define the command to run your application
CMD ["python", "inference_server.py"]