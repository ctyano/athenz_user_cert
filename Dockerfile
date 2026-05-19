# note: never use the :latest tag in a production site
FROM golang:1-alpine AS builder

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies upx cmake g++ make unzip curl git tzdata

RUN cp /usr/share/zoneinfo/Japan /etc/localtime

ARG APP_NAME=athenz-user-cert
ENV APP_NAME=${APP_NAME}
ARG BINARY_NAME=athenzusercert
ENV BINARY_NAME=${BINARY_NAME}
ARG VERSION=test
ENV VERSION=${VERSION}

WORKDIR ${GOPATH}/src/${APP_NAME}

COPY . .

RUN make \
    APP_NAME="${APP_NAME}" BINARY_NAME="${BINARY_NAME}" \
    && mv "${GOPATH}/bin/${BINARY_NAME}" "/usr/bin/${BINARY_NAME}"

RUN /usr/bin/${BINARY_NAME} version

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Alpine For Running Environment
FROM alpine

RUN apk add net-tools openssl

ARG BINARY_NAME=athenzusercert
ENV BINARY_NAME=${BINARY_NAME}

COPY --from=builder /usr/bin/${BINARY_NAME} /usr/bin/${BINARY_NAME}

ENTRYPOINT /usr/bin/${BINARY_NAME}
