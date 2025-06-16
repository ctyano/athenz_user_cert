# note: never use the :latest tag in a production site
FROM golang:1-alpine AS builder

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies upx cmake g++ make unzip curl git tzdata

RUN cp /usr/share/zoneinfo/Japan /etc/localtime

ENV APP_NAME athenz-user-cert

ENV APP_VERSION test

WORKDIR ${GOPATH}/src/${APP_NAME}

COPY . .

RUN go get ./...

RUN go build -o "${APP_NAME}" \
    && mv "${APP_NAME}" "/usr/bin/${APP_NAME}"

RUN /usr/bin/${APP_NAME} version

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Alpine For Running Environment
FROM alpine

RUN apk add net-tools openssl

ENV APP_NAME athenz-user-cert

COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}

ENTRYPOINT /usr/bin/${APP_NAME}

