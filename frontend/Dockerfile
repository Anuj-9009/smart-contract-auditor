# ═══════════════════════════════════════════════════════════
# Frontend Dockerfile — Multi-stage: Build → Serve via Nginx
# ═══════════════════════════════════════════════════════════

# ─── Stage 1: Build ──────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

# Dependencies (cached layer)
COPY package.json package-lock.json ./
RUN npm ci --silent

# Build the production bundle
COPY . .
RUN npm run build

# ─── Stage 2: Serve ──────────────────────────────────────
FROM nginx:1.27-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from Stage 1
COPY --from=build /app/dist /usr/share/nginx/html

# Non-root nginx (optional hardening)
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
