# Builds the ghidra-lx-loader extension .zip.
# Invoke via ./build.sh, which copies the result out of the image.

FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303
ARG GHIDRA_BUILD=Ghidra_12.0.4_build
ARG GRADLE_VERSION=8.5

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH=/opt/gradle/bin:${PATH}

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/gradle.zip \
        "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" && \
    unzip -q /tmp/gradle.zip -d /opt && \
    mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle && \
    rm /tmp/gradle.zip

RUN curl -fsSL -o /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_BUILD}/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "${GHIDRA_INSTALL_DIR}" && \
    rm /tmp/ghidra.zip

WORKDIR /build/ghidra-lx-loader
COPY . .

RUN gradle --no-daemon buildExtension
