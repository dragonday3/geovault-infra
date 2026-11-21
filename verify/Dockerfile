FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
RUN pip install --no-cache-dir --disable-pip-version-check boto3==1.44.9
RUN useradd --uid 10001 --no-create-home verifier
USER 10001
COPY verify.py scan_public.py /
ENTRYPOINT ["python", "/verify.py"]
