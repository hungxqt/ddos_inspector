# Prometheus C++ Library Installation Guide

This guide provides step-by-step instructions for installing the Prometheus C++ client library.

## Prerequisites

Ensure you have the following installed:
- CMake (version 3.10 or higher)
- GCC or Clang compiler with C++11 support
- Git
- Make

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/jupp0r/prometheus-cpp.git
cd prometheus-cpp
```

### 2. Initialize and Update Submodules

```bash
git submodule init
git submodule update
```

### 3. Create Build Directory

```bash
mkdir _build
cd _build
```

### 4. Modify CMakeLists.txt (Optional - Skip Tests)

If you want to skip building tests to speed up compilation:

```bash
nano ../pull/CMakeLists.txt
```

Find the line `add_subdirectory(tests)` and comment it out:
```cmake
# add_subdirectory(tests)
```

### 5. Configure with CMake

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_PULL=ON -DENABLE_PUSH=OFF -DBUILD_SHARED_LIBS=ON
```

**Configuration Options:**
- `DENABLE_PULL=ON`: Enables pull-based metrics (recommended for most use cases)
- `DENABLE_PUSH=OFF`: Disables push gateway support (can be enabled if needed)
- `DBUILD_SHARED_LIBS=ON`: Builds shared libraries

### 6. Build the Library

```bash
make -j$(nproc)
```

### 7. Install the Library

```bash
sudo make install
```

## Verification

To verify the installation was successful, you can check if the library files are installed:

```bash
ldconfig -p | grep prometheus
```

## Usage in Your Project

After installation, you can use the library in your CMake project by adding:

```cmake
find_package(prometheus-cpp CONFIG REQUIRED)
target_link_libraries(your_target prometheus-cpp::pull)
```

## Troubleshooting

- If you encounter permission issues during installation, ensure you have sudo privileges
- If CMake cannot find the library after installation, you may need to update your `CMAKE_PREFIX_PATH`
- For custom installation directories, use `-DCMAKE_INSTALL_PREFIX=/your/custom/path` during configuration

## Additional Resources

- [Prometheus C++ Client Documentation](https://github.com/jupp0r/prometheus-cpp)
- [Prometheus Metrics Best Practices](https://prometheus.io/docs/practices/naming/)
