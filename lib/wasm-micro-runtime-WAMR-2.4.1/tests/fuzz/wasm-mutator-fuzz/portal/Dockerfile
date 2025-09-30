FROM node:16 as builder

WORKDIR /portal
COPY . .

ARG proxy=""

RUN if [ "$proxy" != "" ]; \
    then npm config set proxy "$proxy" && npm config set https-proxy "$proxy"; \
    else echo Do not set proxy; \
    fi
RUN npm install && chmod +x node_modules/.bin/tsc \
    && chmod +x node_modules/.bin/vite \
    && npm run build

FROM nginx:alpine
WORKDIR /portal
COPY --from=builder /portal/dist/ /usr/share/nginx/html/
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf.template /etc/nginx/conf.d

# hadolint ignore=DL3025
CMD /bin/sh -c "envsubst '80' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf" && nginx -g 'daemon off;'