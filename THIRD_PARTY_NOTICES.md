# Third-party notices

SentinelTrace is built on open-source software. This file lists every third-party component that ships with the application at runtime, with its licence. Development-only tools (test runners, linters, build tools) are not distributed and are not listed.

Licence texts are included in each package's distribution (in `node_modules/<package>/` and the Python environment's `*.dist-info/` folders) and are available from the package registries (npmjs.com, pypi.org).

## Notes on specific licences

- **psycopg / psycopg-binary (LGPL-3.0-only):** used unmodified as a separately installed library. Its source is available at https://github.com/psycopg/psycopg. You may replace it with another build of the same library.
- **certifi (MPL-2.0):** used unmodified. Source: https://github.com/certifi/python-certifi.
- All other components use permissive licences (MIT, BSD, Apache-2.0, ISC, PSF, 0BSD, MIT-0, Unlicense).

## Fonts, icons and images

- **Fonts:** no font files are bundled or downloaded. The stylesheet names Inter and JetBrains Mono, which are used only if already installed on the viewer's device, and otherwise falls back to the system fonts. Nothing is loaded from a font service.
- **Icon:** `frontend/public/favicon.svg` is original artwork made for this project.
- **Screenshots:** `docs/screenshots/` show this application running on the project's own synthetic data.
- **Charts:** drawn at runtime by Recharts (MIT). No icon fonts or stock images are used.

## Backend (Python, 67 packages)

| Package | Version | Licence |
|---|---|---|
| agent-detector | 2.0.0 | MIT |
| alembic | 1.20.0 | MIT |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause (Windows only) |
| detect-installer | 0.2.1 | 0BSD |
| dnspython | 2.9.0 | ISC |
| email-validator | 2.3.0 | Unlicense |
| fastapi | 0.143.0 | MIT |
| fastapi-cli | 0.0.32 | MIT |
| fastapi-cloud-cli | 0.26.0 | MIT |
| fastar | 0.12.0 | MIT |
| googleapis-common-protos | 1.75.5 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httptools | 0.9.0 | MIT |
| httpx | 0.28.1 | BSD |
| idna | 3.20 | BSD-3-Clause |
| jinja2 | 3.1.6 | BSD |
| mako | 1.4.3 | MIT |
| markdown-it-py | 4.2.0 | MIT |
| markupsafe | 3.0.4 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| opentelemetry-api | 1.45.1 | Apache-2.0 |
| opentelemetry-exporter-http-transport | 0.66b1 | Apache-2.0 |
| opentelemetry-exporter-otlp-common | 0.66b1 | Apache-2.0 |
| opentelemetry-exporter-otlp-proto-common | 1.45.1 | Apache-2.0 |
| opentelemetry-exporter-otlp-proto-http | 1.45.1 | Apache-2.0 |
| opentelemetry-proto | 1.45.1 | Apache-2.0 |
| opentelemetry-sdk | 1.45.1 | Apache-2.0 |
| opentelemetry-semantic-conventions | 0.66b1 | Apache-2.0 |
| protobuf | 7.36.2 | BSD-3-Clause |
| psycopg | 3.3.6 | LGPL-3.0-only |
| psycopg-binary | 3.3.6 | LGPL-3.0-only |
| pycparser | 3.11 | BSD-3-Clause |
| pydantic | 2.14.0 | MIT |
| pydantic-core | 2.50.0 | MIT |
| pydantic-extra-types | 2.11.1 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| pygments | 2.21.0 | BSD-2-Clause |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| pyyaml | 6.0.3 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rich | 15.0.0 | MIT |
| rich-toolkit | 0.20.6 | MIT |
| rignore | 0.8.1 | MIT |
| sentry-sdk | 2.71.0 | MIT |
| shellingham | 1.5.4 | ISC |
| sqlalchemy | 2.1.4 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typer | 0.27.3 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| tzdata | 2026.5 | Apache-2.0 (Windows only) |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| uvloop | 0.23.0 | Apache-2.0 OR MIT |
| watchfiles | 1.3.0 | MIT |
| websockets | 17.2 | BSD-3-Clause |

## Frontend (JavaScript, 48 packages in the production bundle)

| Package | Version | Licence |
|---|---|---|
| @reduxjs/toolkit | 2.13.0 | MIT |
| @standard-schema/spec | 1.1.0 | MIT |
| @standard-schema/utils | 0.3.0 | MIT |
| @types/d3-array | 3.2.2 | MIT |
| @types/d3-color | 3.1.3 | MIT |
| @types/d3-ease | 3.0.2 | MIT |
| @types/d3-interpolate | 3.0.4 | MIT |
| @types/d3-path | 3.1.1 | MIT |
| @types/d3-scale | 4.0.9 | MIT |
| @types/d3-shape | 3.2.0 | MIT |
| @types/d3-time | 3.0.4 | MIT |
| @types/d3-timer | 3.0.2 | MIT |
| @types/react | 19.3.0 | MIT |
| @types/use-sync-external-store | 0.0.6 | MIT |
| clsx | 2.1.1 | MIT |
| cookie | 1.1.1 | MIT |
| csstype | 3.2.3 | MIT |
| d3-array | 3.2.4 | ISC |
| d3-color | 3.1.0 | ISC |
| d3-ease | 3.0.1 | BSD-3-Clause |
| d3-format | 3.1.2 | ISC |
| d3-interpolate | 3.0.1 | ISC |
| d3-path | 3.1.0 | ISC |
| d3-scale | 4.0.2 | ISC |
| d3-shape | 3.2.0 | ISC |
| d3-time | 3.1.0 | ISC |
| d3-time-format | 4.1.0 | ISC |
| d3-timer | 3.0.1 | ISC |
| decimal.js-light | 2.5.1 | MIT |
| es-toolkit | 1.52.0 | MIT |
| eventemitter3 | 5.0.4 | MIT |
| immer | 11.1.21 | MIT |
| internmap | 2.0.3 | ISC |
| react | 19.3.0 | MIT |
| react-dom | 19.3.0 | MIT |
| react-is | 19.3.0 | MIT |
| react-redux | 9.3.0 | MIT |
| react-router | 7.18.4 | MIT |
| react-router-dom | 7.18.4 | MIT |
| recharts | 3.10.1 | MIT |
| redux | 5.0.1 | MIT |
| redux-thunk | 3.1.0 | MIT |
| reselect | 5.2.0 | MIT |
| scheduler | 0.28.0 | MIT |
| set-cookie-parser | 2.7.2 | MIT |
| tiny-invariant | 1.3.3 | MIT |
| use-sync-external-store | 1.7.0 | MIT |
| victory-vendor | 37.3.6 | MIT AND ISC |

## Container base images

- `python` and `node` official Docker images, and `nginx` and `postgres` official images, each under their own licences (see Docker Hub). They are pulled at build time, not redistributed in this repository.
