# Build stage
FROM python:3.7-slim AS build

# Install build dependencies
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
 && apt-get install -y --no-install-recommends build-essential git

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install Python requirements
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

# Final stage
FROM python:3.7-slim

# Install runtime dependencies
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
    && apt-get -y --no-install-recommends install \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from build stage
COPY --from=build /opt/venv /opt/venv

# Copy defender code to /opt/defender/defender
COPY defender/ /opt/defender/defender/
COPY model.sav /opt
COPY selected_features.txt /opt
RUN tar -c --exclude='./defender/.ipynb_checkpoints' --exclude='./defender/pe-machine-learning-dataset' -f - -C /opt/defender/defender . | tar -xvf - -C /opt/defender/defender


# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"
ENV MODEL_SAV_PATH="/opt/model.sav"
ENV SELECTED_FEATURES_PATH="/opt/selected_features.txt"



# Open port 8080
EXPOSE 8080

# Change working directory
WORKDIR /opt

# Run code
CMD ["python","-m","defender"]