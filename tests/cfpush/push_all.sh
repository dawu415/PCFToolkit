#!/bin/bash
for i in "aspnet-mvc-sample-app" "hwc-dotnetframework-sample-app" "golang-sample-app" "ruby-sample-app" "spring-music";
do
   echo "Process $i..."
   echo "    - Creating Random File.."
   base64 /dev/urandom | head -c 26214400 > $i/data.file
   echo "    - Starting CF Push $1"
   (time ./$i/push.sh sample_${i}_${1}) &> ${i}_${1}_push.log
done 
