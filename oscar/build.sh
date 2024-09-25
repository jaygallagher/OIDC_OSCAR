
docker run --rm -it \
        ${MAP_NETWORK} \
        --name oscarOIDC \
        --security-opt label=disable \
        --volume="`pwd`:/oscar:rw" \
        --volume="`pwd`/bash_history:/root/.bash_history:rw" \
	--sysctl net.ipv6.conf.all.disable_ipv6=1 \
        maven:3.6.3-openjdk-11 bash

