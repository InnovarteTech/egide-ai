FROM node:20-alpine AS build
WORKDIR /app
COPY . .
ARG LANDING_PUBLIC_URL=""
ENV LANDING_PUBLIC_URL=$LANDING_PUBLIC_URL
RUN node build.mjs && node check.mjs

FROM nginx:1.27-alpine
RUN printf 'server {\n  listen 80;\n  root /usr/share/nginx/html;\n  location / { try_files $uri $uri/ $uri.html =404; }\n  location = / { try_files /index.html =404; }\n}\n' > /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
