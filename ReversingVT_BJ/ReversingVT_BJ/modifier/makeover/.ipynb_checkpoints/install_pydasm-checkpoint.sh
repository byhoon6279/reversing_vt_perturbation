#!/bin/bash

# 실행할 경로로 이동
cd enhanced-binary-randomization/libdasm-1.5_orp/pydasm || exit

# 기존 빌드 정리
echo "[+] Cleaning previous build..."
python setup.py clean
rm -rf build
rm -rf dist
rm -rf *.egg-info

# 새로 빌드 & 설치
echo "[+] Building package..."
python setup.py build

echo "[+] Installing package..."
python setup.py install --user

echo "[+] Done!"

