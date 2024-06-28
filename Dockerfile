# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Set the working directory in the container to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

RUN mkdir -p ./models

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Define the entrypoint script
ENTRYPOINT ["python", "ml_classifier.py"]

# Define default arguments (can be overridden by command line arguments)
CMD ["--path", "."]