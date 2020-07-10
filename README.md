
```
$ go build
$ sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip ./ripple20
$ ./ripple20 -delay 16ms 172.16.0.0/12 2>&1 | tee scan_results.txt
```

```
Usage of ./ripple20:
  -delay duration
                    delay between probes (default 8ms)
  -ignore-mss
                    ignore mss (useful for MSS-overriding NATs)
  -port int
                    source port (default: random)
```
