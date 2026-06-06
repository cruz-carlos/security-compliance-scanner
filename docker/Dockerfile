# Use the official AWS Lambda Python base image
FROM public.ecr.aws/lambda/python:3.12

# Copy scanner source files into the Lambda task root
COPY scanner/ ${LAMBDA_TASK_ROOT}/

# Install dependencies
RUN pip install boto3 requests --no-cache-dir

# Lambda handler — points to main.py's handler function
CMD ["main.handler"]
