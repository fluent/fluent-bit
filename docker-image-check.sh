#!/bin/sh

VERSION="1.3"
IMAGE_NAMES=("fluent/fluent-bit" "fluent/fluent-bit-inotify-disabled")

for imageName in "${IMAGE_NAMES[@]}"
do
	echo "==> Checking Fluent-Bit reported version by '${imageName}' image:"

	docker run -ti ${imageName}:${VERSION} /fluent-bit/bin/fluent-bit --version
	docker run -ti ${imageName}:${VERSION}-debug /fluent-bit/bin/fluent-bit --version
	
	echo "==> Checking INOTIFY flag presence in '${imageName}' Fluent-Bit image:" 
	
	# for full debug only:
	#docker run -ti ${imageName}:${VERSION} /fluent-bit/bin/fluent-bit --sosreport
	#docker run -ti ${imageName}:${VERSION}-debug /fluent-bit/bin/fluent-bit --sosreport
	
	docker run -ti ${imageName}:${VERSION} /fluent-bit/bin/fluent-bit --sosreport | grep "INOTIFY"
	docker run -ti ${imageName}:${VERSION}-debug /fluent-bit/bin/fluent-bit --sosreport | grep "INOTIFY"
	
	# for full debug only:
	#docker run -ti ${imageName}:${VERSION} /fluent-bit/bin/fluent-bit --help
	#docker run -ti ${imageName}:${VERSION}-debug /fluent-bit/bin/fluent-bit --help
	
	docker run -ti ${imageName}:${VERSION} /fluent-bit/bin/fluent-bit --help | grep "INOTIFY"
	docker run -ti ${imageName}:${VERSION}-debug /fluent-bit/bin/fluent-bit --help | grep "INOTIFY"
done

echo "Checking finished"
