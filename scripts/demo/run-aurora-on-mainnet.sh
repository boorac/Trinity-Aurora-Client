mprof run --multiprocess --include-children trinity  --sync-mode=light --disable-discovery --disable-upnp --disable-request-server --disable-rpc --disable-blacklistdb  --aurora 10000 500 1  2>&1 | tee -a ram-usage-10000.log

