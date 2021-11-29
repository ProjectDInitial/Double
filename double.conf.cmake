log:
    error:                  @DOUBLE_ERRORLOG_PATH@
    access:                 @DOUBLE_ACCESSLOG_PATH@

http:
    host:                   0.0.0.0
    port:                   9999

    # request and response options
    maxheadersize:          2048    # request max headers size 
    maxbodysize:            8192    # request max body size
    request_timeout:        20000   
    response_timeout:       20000
    read_timeout:           30000   # connection read timeout 
    write_timeout:          30000   # connection write timeout

    tcp:
       keepalive_time:      90
       keepalive_intvl:     3
       keepalive_probes:    10 
       nodelay:             0 

    # cross-origin resource sharing enable if this option is set
    #
    # NOTES: '*' is a special symbol in YAML, please use '"*"'.
    #        such as 'key : "*"'
    cors:
        origins:
            - "*" 

    # ssl enable if this option is set
    #ssl:            
    #    certificate:                    @DOUBLE_INSTALL_PREFIX@/cert/double-cert.pem
    #    privatekey:                     @DOUBLE_INSTALL_PREFIX@/cert/double-pk.pem

    # signature verification enable if this option is set 
    #signature:
    #    # message digest method(MD5, SHA256, SHA512...) 
    #    md_method:                      MD5
    #    # message digest secret(salt)
    #    md_secret:                      123 
