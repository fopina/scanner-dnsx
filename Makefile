build:
	docker build -t tmp-$(notdir $(CURDIR)) .

cleantest:
	rm -fr testdata/output

test: cleantest
	go run main.go --all --output testdata/output/ -- -v testdata/inp1.txt

test2: cleantest
	go run main.go --all -l 3 --output testdata/output/ -- -v testdata/inp1.txt

dockertest: cleantest build
	docker run --rm -v $(PWD)/testdata:/input tmp-$(notdir $(CURDIR)) /input/inp1.txt
