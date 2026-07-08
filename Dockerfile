ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM node:22-alpine AS web-build

WORKDIR /src/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY VERSION /src/VERSION
COPY web ./
RUN NEXT_PUBLIC_APP_VERSION="$(cat /src/VERSION)" npm run build


FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS go-build

ARG TARGETARCH

WORKDIR /src/go-backend

COPY go-backend/go.mod go-backend/go.sum ./
RUN go mod download

COPY go-backend ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/chatgpt2api-go ./cmd/chatgpt2api


FROM --platform=$TARGETPLATFORM nginx:1.29-alpine

RUN apk add --no-cache ca-certificates nodejs tzdata

WORKDIR /app

RUN mkdir -p /app/scripts

COPY --from=go-build /out/chatgpt2api-go /usr/local/bin/chatgpt2api-go
COPY --from=web-build /src/web/out /usr/share/nginx/html
COPY go-backend/deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY go-backend/deploy/entrypoint.sh /usr/local/bin/chatgpt2api-go-entrypoint
COPY scripts/sentinel_token_helper.mjs /app/scripts/sentinel_token_helper.mjs
COPY config.json /app/config.json
COPY VERSION /app/VERSION

RUN mkdir -p /app/data && chmod +x /usr/local/bin/chatgpt2api-go-entrypoint

ENV CHATGPT2API_GO_PORT=8001 \
    CHATGPT2API_CONFIG_FILE=/app/config.json \
    CHATGPT2API_DATA_DIR=/app/data

EXPOSE 80

CMD ["chatgpt2api-go-entrypoint"]
