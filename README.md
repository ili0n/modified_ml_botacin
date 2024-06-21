# Modified ML Botacin

This project uses a Docker container to run a Python script for machine learning classification.

## Directory Structure

The project should have the following directory structure:
The `goodware` and `malware` directories should be in the same directory as the Dockerfile and contain the goodware and malware files respectively.

## Building the Docker Image

To build the Docker image, navigate to the directory containing the Dockerfile and run the following command in your terminal:

```bash
docker build -t your-image-name .

docker run your-image-name