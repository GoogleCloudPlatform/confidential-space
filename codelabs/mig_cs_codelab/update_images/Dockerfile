# Use a base image with bash
FROM bash:5.2

# Optional: Install gcloud if your script needs it
FROM google/cloud-sdk:slim

# Set the working directory
WORKDIR /app

# Copy the script into the container
COPY update_images_script.sh .

# Make sure it's executable (although already done locally)
RUN chmod +x ./update_images_script.sh

# Command to run when the container starts
CMD ["./update_images_script.sh"]
