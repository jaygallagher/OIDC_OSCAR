
docker run --rm -it \
        ${MAP_NETWORK} \
        --name springboottestbuild \
        --security-opt label=disable \
        --volume="`pwd`:/app:rw" \
	--sysctl net.ipv6.conf.all.disable_ipv6=1 \
        maven:3.9.9-eclipse-temurin-22-jammy bash 

