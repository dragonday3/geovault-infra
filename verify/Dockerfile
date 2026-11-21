FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN pip install --no-cache-dir --disable-pip-version-check boto3==1.44.9
RUN useradd --uid 10001 --no-create-home verifier
USER 10001
COPY verify.py scan_public.py /
ENTRYPOINT ["python", "/verify.py"]
