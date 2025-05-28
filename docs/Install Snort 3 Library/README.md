# Snort 3 Installation Guide

This guide provides step-by-step instructions for installing Snort 3 from source, which is required for building and running the DDoS Inspector plugin.

## Prerequisites

Before installing Snort 3, you must install the required dependencies. We provide a script to automate this process:

```bash
./scripts/install_dependencies.sh
```

## Dependencies Overview

Snort 3 requires the following dependencies (as specified in the [official documentation](https://github.com/snort3/snort3#dependencies)):

### Build Tools
- **CMake** - Build system for compiling from source
- **g++ >= 7** - C++17 compiler (or compatible alternative)
- **flex >= 2.6.0** - JavaScript syntax parser ([GitHub](https://github.com/westes/flex))
- **pkgconfig** - Dependency location tool ([Website](https://www.freedesktop.org/wiki/Software/pkg-config/))

### Core Libraries
- **DAQ** - Packet I/O abstraction layer ([GitHub](https://github.com/snort3/libdaq))
- **libdnet** - Network utility functions ([GitHub](https://github.com/dugsong/libdnet.git))
- **LuaJIT** - Configuration and scripting engine ([Website](http://luajit.org))
- **OpenSSL** - Cryptographic functions for signatures and SSL detection ([Website](https://www.openssl.org/source/))
- **libpcap** - Packet capture for tcpdump-style logging ([Website](http://www.tcpdump.org))
- **PCRE2** - Regular expression pattern matching ([Website](http://www.pcre.org))
- **zlib** - Data decompression library ([Website](http://www.zlib.net))

### Optional Dependencies
- **hwloc** - CPU affinity management ([Website](https://www.open-mpi.org/projects/hwloc/))

## Installation Steps

### 1. Install Dependencies
First, ensure all required dependencies are installed:

```bash
# Run dependency installation script
sudo ./scripts/install_dependencies.sh
```

### 2. Clone Snort 3 Repository
```bash
git clone https://github.com/snort3/snort3.git
cd snort3/
```

### 3. Configure Build
Configure the build system with the desired installation prefix:

```bash
./configure_cmake.sh --prefix=/usr/local/snort3/
```

**Note:** The prefix `/usr/local/snort3/` is recommended as it matches the expected path used by the DDoS Inspector plugin.

### 4. Compile and Install
```bash
cd build
sudo make -j $(nproc) install
```

The `-j $(nproc)` flag uses all available CPU cores to speed up compilation.

### 5. Verify Installation
After installation, verify that Snort 3 is properly installed:

```bash
# Check if snort binary is available
/usr/local/snort3/bin/snort --version

# Check for required headers (needed for plugin development)
ls -la /usr/local/snort3/include/snort/
```

## Post-Installation Configuration

### Environment Setup
Add Snort 3 to your system PATH:

```bash
echo 'export PATH="/usr/local/snort3/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Verify Plugin Development Environment
Ensure the development headers are available for building the DDoS Inspector plugin:

```bash
# Check for essential header files
ls /usr/local/snort3/include/snort/framework/inspector.h
ls /usr/local/snort3/include/snort/framework/module.h
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   - **Error:** `configure: error: required library not found`
   - **Solution:** Ensure all dependencies are installed via the `install_dependencies.sh` script

2. **Compiler Version**
   - **Error:** `error: This file requires compiler and library support for the ISO C++ 2017 standard`
   - **Solution:** Install a newer version of g++ (>= 7.0)

3. **Permission Issues**
   - **Error:** `Permission denied` during installation
   - **Solution:** Use `sudo` for the installation step: `sudo make install`

4. **CMake Version**
   - **Error:** `CMake 3.x or higher is required`
   - **Solution:** Update CMake to a newer version

### Getting Help

If you encounter errors during installation:
1. Check the build logs for specific error messages
2. Search for the error message online or use AI assistants like ChatGPT
3. Consult the [official Snort 3 documentation](https://github.com/snort3/snort3)
4. Check the [Snort community forums](https://www.snort.org/community)

## Next Steps

After successfully installing Snort 3:
1. Build the DDoS Inspector plugin using `./scripts/build_project.sh`
2. Deploy the plugin using `./scripts/deploy.sh`
3. Configure Snort with the provided `snort_ddos_config.lua` file
4. Test the installation with the example configurations

## Related Documentation

- [DDoS Inspector Plugin Architecture](../PHASE02_DS/ddos_inspector_architecture.md)
- [Environment Validation](../env_validation.md)
- [Build Project Documentation](../../scripts/build_project.sh)