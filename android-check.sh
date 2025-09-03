#!/bin/bash
docker run -d --rm --name android-emu -e ADBKEY="$(cat ~/.android/adbkey)" --device /dev/kvm -p 8554:8554 -p 5555:5555 us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:30.1.2
CID=$(docker ps -qf name=^/android-emu$)
if [ -z "$CID" ]; then
    echo "Docker emu did not start"
fi
docker logs -f "$CID" > emulator.log 2>&1 &
sleep 20 && adb connect 127.0.0.1:5555
scrcpy -s 127.0.0.1:5555
docker rm -f $CID
