run:
	@if [ $$(docker ps -a -q -f name=ghost-docker) ]; then \
		echo "🟡 Container 'ghost-docker' already exists. Attaching..."; \
		docker start -ai ghost-docker; \
	else \
		echo "🟢 Starting new container 'ghost-docker'..."; \
		docker run -it --name ghost-docker -v /home/xuehuanhuan/source-sink-ghidra/sample:/samples ghost-image; \
	fi

