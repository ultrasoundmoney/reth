#!/usr/bin/env bash

set -euo pipefail

REPOSITORY="ultrasoundorg/reth"
TAG="${1:-$(git rev-parse --short=9 HEAD)}"
IMAGE="${REPOSITORY}:${TAG}"

echo "Building ${IMAGE}..."
docker buildx build --platform linux/amd64 -t "${IMAGE}" -f Dockerfile .

echo "Pushing ${IMAGE}..."
docker push "${IMAGE}"
