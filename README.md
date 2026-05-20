# bm_rtmp_bridge
RTMP bridge for use with Blackmagic Camera and OBS with AV-Sync

# How to use
In Blackmagic Camera import custom stream settings and set the backend to your IP. An example stream config file can be found in this repo. In OBS add a media source and set it to ```rtmp://localhost:1935/live/iphone```. Make sure ```local file``` is deactivated. To use ```bm_rtmp_bridge_avsync.exe``` you might have to exclude it from the firewall.

# How to compile
For Windows
```
g++ -O2 -o bm_rtmp_bridge_avsync.exe bm_rtmp_bridge_avsync.cpp -lws2_32 -std=c++17
```

For Linux/MacOS
```
g++ -O2 -o bm_rtmp_bridge_avsync bm_rtmp_bridge_avsync.cpp -std=c++17 -lpthread
```
