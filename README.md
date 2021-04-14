# Double
A HTTP remote event service, client can listen or trigger the specified event on the service by HTTP protocol. make HTTP server push easier.

**NOTES: Double depend POISX**

## 1. BUILDING AND INSTALLATION

### CMAKE (UNIX)
```
  $ mkdir build && cd build
  $ cmake ..     
  $ make install
```

### CMAKE (General)

```
  # Build type (default is 'Release')
  CMAKE_BUILD_TYPE
  
  # Install prefix 
  CMAKE_INSTALL_PREFIX
```

The following 'Double' specific CMake variables are as follows
```
  # Libevent binary directory
  DOUBLE_LIBEVENT_BINARY_DIR 
  
  # Libevent include directory
  DOUBLE_LIBEVENT_INCLUDE_DIR
```

