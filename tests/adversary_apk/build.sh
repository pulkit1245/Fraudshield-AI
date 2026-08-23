#!/bin/bash
set -e
export ANDROID_HOME=/Users/pulkitverma/Library/Android/sdk
export BUILD_TOOLS=$ANDROID_HOME/build-tools/35.0.0
export PLATFORM=$ANDROID_HOME/platforms/android-35/android.jar

cd /Users/pulkitverma/Developer/Fraudshield-AI/tests/adversary_apk

mkdir -p build/classes build/gen

echo "Compiling resources..."
touch AndroidManifest.xml # Ensure timestamp update
$BUILD_TOOLS/aapt2 compile --dir res -o build/res.zip || echo "No resources"
if [ -f build/res.zip ]; then
    $BUILD_TOOLS/aapt2 link -I $PLATFORM --manifest AndroidManifest.xml --java build/gen -o build/app-unaligned.apk build/res.zip
else
    $BUILD_TOOLS/aapt2 link -I $PLATFORM --manifest AndroidManifest.xml --java build/gen -o build/app-unaligned.apk
fi

echo "Compiling Java..."
javac -source 8 -target 8 -Xlint:-options -bootclasspath $PLATFORM -d build/classes src/com/fraudshield/adversary/MainActivity.java build/gen/com/fraudshield/adversary/R.java || javac -source 8 -target 8 -Xlint:-options -bootclasspath $PLATFORM -d build/classes src/com/fraudshield/adversary/MainActivity.java

echo "Converting to DEX..."
$BUILD_TOOLS/d8 --lib $PLATFORM --output build/ build/classes/com/fraudshield/adversary/*.class

echo "Packaging..."
cd build
zip -uj app-unaligned.apk classes.dex
cd ..

echo "Zipalign..."
$BUILD_TOOLS/zipalign -f 4 build/app-unaligned.apk build/app-aligned.apk

echo "Signing..."
# Create a debug keystore if not exists
if [ ! -f debug.keystore ]; then
  keytool -genkey -v -keystore debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
fi
$BUILD_TOOLS/apksigner sign --ks debug.keystore --ks-pass pass:android build/app-aligned.apk

cp build/app-aligned.apk AdversarialTest.apk
echo "Success! AdversarialTest.apk generated."
