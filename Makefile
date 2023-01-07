build:
	go mod download
	go generate
	CGO_ENABLED=0 go build

clean:
	rm -f *.o zebra-bpf-dplane-example

deploy:
	sudo containerlab -t topo.yaml deploy

redeploy:
	sudo containerlab -t topo.yaml deploy --reconfigure

destroy:
	sudo containerlab -t topo.yaml destroy

docker-image:
	docker build -t yutarohayakawa/zebra-bpf-dplane-example:$(shell git rev-parse --short HEAD) .
