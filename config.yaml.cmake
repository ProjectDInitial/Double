# A file for configured Double
log:
    error:                  @DOUBLE_ERRORLOG_PATH@
    access:                 @DOUBLE_ACCESSLOG_PATH@

http:
    # Required
    host:                   0.0.0.0
    port:                   9999

    ## Options 
    #request_timeout:        300 
    #response_timeout:       2000                
    #maxheadersize:          2000        # Max request headers size
    #maxbodysize:            4000        # Max request body size

    #read_timeout:           5000        # Connection read timeout
    #read_buffer_size:       4096        # Connection read buffer size 

    #write_timeout:          5000        # Connection write timeout
    #write_buffer_size:      65536       # Connection write buffer size

    #tcp:
    #    keepalive_time:                 300
    #    keepalive_intvl:                60
    #    keepalive_probes:               3
    #    nodelay:                        false      # Nagle 

    # Cross-Origin resource sharing 
    # Only effective on request 'host:port/event/listen'
    #
    # NOTES:(*) is a special symbol on YAML, if you want
    #       to allow all origins, please use ("*"),such as
    #
    #       origins:
    #           - "*"
    
    cors:
        - 1
        - 2
        - 344
    #cors:
    #    origins:
    #        - www.hosta.com
    #        - www.hostb.com
    #        - www.hostc.com


    # Security socket layer setting

    #ssl:            
    #    certificate:                    ../../cert/cert.pem
    #    privatekey:                     ../../cert/rsa-private.pem


    #partners:
    #    - id:                           P1
    #      secret:                       P1secret
    #    
    #    - id:                           P2
    #      secret:                       P2secret
