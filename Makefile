SRC = ./ssl.js ./tests/test.js

build: lint test

lint: $(SRC)
	@./node_modules/.bin/jshint $^

test:
	@./node_modules/.bin/mocha tests
