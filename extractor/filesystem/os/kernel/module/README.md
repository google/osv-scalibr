# Test Data Generation from Linux Source Code

This README provides the steps to reproduce the creation of the test data files, which were generated starting from the Linux source code.

## Steps to Reproduce

### 1. Download the Linux Source Code
   - Download the desired version of the Linux source code (e.g., `linux-source-5.15.0.tar.bz2`).

### 2. Install Required Dependencies
   - Install the necessary dependencies to build the kernel modules (e.g. `sudo apt install build-essential linux-headers-$(uname -r) linux-source flex bison`)

### 3. Compile Kernel Modules
   - Compile the modules (e.g. `make modules`)
