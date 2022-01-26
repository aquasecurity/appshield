.PHONY: metadata_lint
metadata_lint:
	go run ./tools/lint/

.PHONY: generate_missing_docs
generate_missing_docs:
	go run ./tools/avd_generator