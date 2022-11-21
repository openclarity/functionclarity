
GOLANGCI_VERSION = 1.49.0
LICENSEI_VERSION = 0.5.0



bin/licensei: bin/licensei-${LICENSEI_VERSION}
	@ln -sf licensei-${LICENSEI_VERSION} bin/licensei
bin/licensei-${LICENSEI_VERSION}:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s v${LICENSEI_VERSION}
	@mv bin/licensei $@

.PHONY: license-check
license-check: bin/licensei ## Run license check
	./bin/licensei check
	./bin/licensei header


bin/golangci-lint: bin/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} bin/golangci-lint

bin/golangci-lint-${GOLANGCI_VERSION}:
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | bash -s -- -b ./bin/ v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@


.PHONY: lint
lint: bin/golangci-lint ## Run linter
	./bin/golangci-lint run -v

.PHONY: test
test: ## Run Unit Tests
	@(go test -v -covermode=atomic -coverprofile=unit-coverage.out ./cmd/... ./pkg/...)

.PHONY: check
check: lint test

.PHONY: fix
fix: bin/golangci-lint ## Fix lint violations
	./bin/golangci-lint run --fix
