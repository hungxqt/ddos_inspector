#!/bin/bash
set -e  # Exit on any error

# Function to clone only if directory doesn't exist or is empty
safe_git_clone() {
  REPO_URL=$1
  TARGET_DIR=$2
  if [ -d "$TARGET_DIR" ]; then
    if [ -z "$(ls -A "$TARGET_DIR")" ]; then
      echo "[*] Directory '$TARGET_DIR' exists but is empty. Cloning..."
      git clone "$REPO_URL" "$TARGET_DIR"
    else
      echo "[!] Skipping clone: '$TARGET_DIR' already exists and is not empty."
    fi
  else
    echo "[*] Cloning into '$TARGET_DIR'..."
    git clone "$REPO_URL" "$TARGET_DIR"
  fi
}

echo "[*] Updating system and installing essential build tools..."
sudo apt update && sudo apt install -y \
  build-essential \
  git \
  autoconf \
  libtool \
  libpcap-dev \
  libpcre2-dev \
  zlib1g-dev \
  pkg-config \
  bison \
  libssl-dev \
  libhwloc-dev \
  curl \
  flex \
  g++ \
  libluajit-5.1-dev \
  check \
  cmake \
  gcc \
  make \
  libc6-dev \
  liblzma-dev

# Check and upgrade CMake if older than 3.14.0
echo "[*] Checking for CMake version..."
CMAKE_VERSION=$(cmake --version | grep -oP '\d+\.\d+\.\d+')
REQUIRED_CMAKE_VERSION="3.14.0"
if dpkg --compare-versions "$CMAKE_VERSION" lt "$REQUIRED_CMAKE_VERSION"; then
  echo "[-] CMake too old, installing from source..."
  cd /tmp
  curl -LO https://github.com/Kitware/CMake/releases/download/v3.27.9/cmake-3.27.9.tar.gz
  tar -xzvf cmake-3.27.9.tar.gz
  cd cmake-3.27.9
  ./bootstrap && make -j"$(nproc)" && sudo make install
fi

echo "[*] Building libdaq..."
cd /opt
safe_git_clone https://github.com/snort3/libdaq.git libdaq
cd libdaq
./bootstrap
./configure
make -j"$(nproc)"
sudo make install

echo "[*] Building libdnet..."
cd /opt
safe_git_clone https://github.com/dugsong/libdnet.git libdnet
cd libdnet
./configure
make -j"$(nproc)"
sudo make install

echo "[*] Building LuaJIT..."
cd /opt
safe_git_clone https://luajit.org/git/luajit.git luajit-2.0
cd luajit-2.0
make -j"$(nproc)"
sudo make install

echo "[*] Checking g++ version for C++17 support..."
GPP_VERSION=$(g++ -dumpversion)
REQUIRED_GPP_MAJOR=7
if [[ ${GPP_VERSION%%.*} -lt $REQUIRED_GPP_MAJOR ]]; then
  echo "[-] g++ too old, installing g++-10..."
  sudo apt install -y g++-10
  sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 100
fi

echo "[*] Checking and installing OpenSSL from source if needed..."
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
REQUIRED_OPENSSL_VERSION="1.1.1"
if dpkg --compare-versions "$OPENSSL_VERSION" lt "$REQUIRED_OPENSSL_VERSION"; then
  echo "[-] OpenSSL too old, installing from source..."
  cd /tmp
  curl -O https://www.openssl.org/source/openssl-1.1.1w.tar.gz
  tar -xzvf openssl-1.1.1w.tar.gz
  cd openssl-1.1.1w
  ./config
  make -j"$(nproc)"
  sudo make install
  sudo ldconfig
fi

echo "[*] Finalizing..."
sudo ldconfig

echo "[✓] All Snort 3 dependencies installed successfully!"