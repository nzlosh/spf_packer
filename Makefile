.PHONY: all
all: test build

.PHONY: clean
clean:
	@echo -e "\e[36mCleaning up build files.\e[0m"

.PHONY: test
test:
	@echo -e "\e[36mRunning unit tests (requires internet access with working dns resolution).\e[0m"
	@go test

.PHONY: build
build:
	@echo -e "\e[36mBuilding project.\e[0m"
	@go build

.PHONY: help
help:
	@echo Available targets
	@echo -e "\e[35mall\e[0m - run test and build targets."
	@echo -e "\e[35mclean\e[0m - remove build files."
	@echo -e "\e[35mbuild\e[0m - compile project."
	@echo -e "\e[35mtest\e[0m - run project tests."
	@echo -e "\e[35mhelp\e[0m - this help."

