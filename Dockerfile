FROM alpine:latest as pre-build

COPY . /usr/local/apisix-dashboard

RUN set -x \
    && apk add --no-cache --virtual .builddeps git \
    && cd /usr/local/apisix-dashboard && git clean -Xdf \
    && rm -f ./.githash && git log --pretty=format:"%h" -1 > ./.githash

FROM golang:1.19 as api-builder

ARG ENABLE_PROXY=false

WORKDIR /usr/local/apisix-dashboard

COPY --from=pre-build /usr/local/apisix-dashboard .

RUN if [ "$ENABLE_PROXY" = "true" ] ; then go env -w GOPROXY=https://goproxy.io,direct ; fi \
    && go env -w GO111MODULE=on \
    && CGO_ENABLED=0 ./api/build.sh

FROM node:16-alpine as fe-builder

ARG ENABLE_PROXY=false

WORKDIR /usr/local/apisix-dashboard

COPY --from=pre-build /usr/local/apisix-dashboard .

WORKDIR /usr/local/apisix-dashboard/web

COPY ./html ../output/html

FROM alpine:latest as prod

ARG ENABLE_PROXY=false

RUN if [ "$ENABLE_PROXY" = "true" ] ; then sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories ; fi

WORKDIR /usr/local/apisix-dashboard

COPY --from=api-builder /usr/local/apisix-dashboard/output/ ./

COPY --from=fe-builder /usr/local/apisix-dashboard/output/ ./

RUN mkdir logs

EXPOSE 9000

CMD [ "/usr/local/apisix-dashboard/manager-api" ]