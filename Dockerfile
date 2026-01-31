FROM python:3.10-slim

# Set working directory
WORKDIR /sandbox

# Set dummy environment variable for exfiltration simulation
ENV SECRET_KEY=TEST_DUMMY_123

# Copy payload at runtime via volume mount
CMD ["python", "/sandbox/payload.py"]
