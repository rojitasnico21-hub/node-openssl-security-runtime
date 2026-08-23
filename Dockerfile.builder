# syntax=docker/dockerfile:1.7
ARG NODE_BUILD_BASE=node:22.23.2-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a
FROM ${NODE_BUILD_BASE}

ARG TEXT_TEMPLATE_DEB_SHA256
COPY libtext-template-perl_1.61-1_all.deb /tmp/libtext-template-perl.deb

RUN set -eux; \
    printf '%s  %s\n' "${TEXT_TEMPLATE_DEB_SHA256}" /tmp/libtext-template-perl.deb | sha256sum -c -; \
    test "$(dpkg-deb -f /tmp/libtext-template-perl.deb Package)" = libtext-template-perl; \
    test "$(dpkg-deb -f /tmp/libtext-template-perl.deb Version)" = 1.61-1; \
    test "$(dpkg-deb -f /tmp/libtext-template-perl.deb Architecture)" = all; \
    dpkg-deb -x /tmp/libtext-template-perl.deb /opt/text-template; \
    rm /tmp/libtext-template-perl.deb

ENV PERL5LIB=/opt/text-template/usr/share/perl5
