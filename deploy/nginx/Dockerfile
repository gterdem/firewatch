# nginx sidecar image for FireWatch.
#
# Multi-stage build:
#   Stage 1 (node-builder): compiles the React/Vite frontend into a
#     static dist/ directory.
#   Stage 2 (runtime): nginx:alpine serving the compiled SPA + proxying
#     API calls to the loopback FireWatch API.
#
# This image is ONLY the UI/proxy layer.  The FireWatch API is handled by
# the `firewatch` service; this image never runs Python.
#
# Network topology (docker-compose.yml):
#   network_mode: "service:firewatch" — nginx and the API share the same
#   network namespace, so nginx proxies to 127.0.0.1:8000 on their shared
#   loopback interface.  The host port (8080 by default) is published on
#   the `firewatch` service entry (not here — the shared-netns container
#   cannot declare its own ports).

# --------------------------------------------------------------------------
# Stage 1: frontend build
# --------------------------------------------------------------------------
FROM node:22-alpine AS node-builder

WORKDIR /frontend

# Install dependencies first (cache-friendly layer).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --prefer-offline

# Copy the rest of the frontend source and build.
COPY frontend/ ./
RUN npm run build

# dist/ now contains the compiled SPA (index.html + hashed assets).

# --------------------------------------------------------------------------
# Stage 2: nginx runtime
# --------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# Remove the default nginx config.
RUN rm /etc/nginx/conf.d/default.conf

# Install the compiled SPA.
COPY --from=node-builder /frontend/dist /usr/share/nginx/html

# Install the FireWatch nginx config (proxy + SPA fallback).
COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf

# nginx listens on port 80; the compose file publishes the host port
# on the `firewatch` service (shared netns — see docker-compose.yml).
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
