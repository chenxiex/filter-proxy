#!/bin/bash
yes "" | openssl req -newkey rsa:2048 -nodes -keyout test/example.key -x509 -days 365 -out test/example.crt