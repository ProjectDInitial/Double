# Double
'Double' is a remote event service based on HTTP protocol. HTTP server call this service can push events to client easily, and HTTP client(especially 'web-browser') also can be received events from server easily. 

NOTES: This service only supports unix/linux

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
  # Specify the installation path (default is 'CMAKE_INSTALL_PREFIX/double')
  DOUBLE_INSTALL_PREFIX

  # Specify the libevent binary directory
  DOUBLE_LIBEVENT_BINARY_DIR 
  
  # Specify the libevent include directory
  DOUBLE_LIBEVENT_INCLUDE_DIR
```

