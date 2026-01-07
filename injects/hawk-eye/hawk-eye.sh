#!/bin/bash

docker run -it --rm -v /home/blue/injects/hawk-eye/results:/app/results -v /home/blue/injects/hawk-eye/connection.yml:/app/connection.yml -v /home/blue/injects/hawk-eye/fingerprint.yml:/app/fingerprint.yml --add-host=host.docker.internal:host-gateway rohitcoder/hawk-eye --connection /app/connection.yml --fingerprint /app/fingerprint.yml --json /app/results/results.json all