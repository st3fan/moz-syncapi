# Just a convenient way to do some automation

docker-build:
	docker build -t st3fan/moz-syncapi .

docker-run:
	docker run --publish-all --rm st3fan/moz-syncapi
