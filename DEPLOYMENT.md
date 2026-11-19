# Web dashboard deployment

## Local test

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python web_app.py
```

Open `http://127.0.0.1:5000`. The dashboard runs the existing scanner functions against the machine/container running the web app. It does not scan the browser user's device.

## Free Render deployment

1. Add these deployment files to the GitHub repository: `web_app.py`, `templates/index.html`, `requirements.txt`, `Dockerfile`, `.dockerignore`, and `render.yaml`, plus `service_scanner.py`.
2. Push the changes to GitHub.
3. In Render, create a new Blueprint from the repository, review the service, and deploy the free instance.
4. Open the generated `onrender.com` URL and wait for the first cold start.

The free instance can spin down when idle and has an ephemeral filesystem. Reports are generated in memory for download after each scan; they are not permanent records. The service is deliberately run as a non-root user. As a result, checks requiring root visibility or elevated access may be incomplete in the hosted container. The dashboard reports the container context, not the visitor's own computer.

## Security scope

The API accepts only a fixed allowlist of scanner IDs and does not accept shell commands, paths, or arbitrary targets. It is a detection-only tool. Do not expose this as a privileged remote shell or use it to scan systems without authorization.
