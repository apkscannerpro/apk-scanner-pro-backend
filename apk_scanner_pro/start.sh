#!/bin/bash
gunicorn -w 1 -b 0.0.0.0:10000 apk_scanner_pro.api_server:app
