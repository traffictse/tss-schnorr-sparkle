TASKS = luban_manager sparkle_test

debug:
	cargo build
	for task in $(TASKS); do \
		rm -f ./built/$$task; \
		rsync -avP target/debug/$$task ./built/; \
	done

release:
	cargo build --release
	for task in $(TASKS); do \
		rm -f ./built/$$task; \
		rsync -avP target/release/$$task ./built/; \
	done

.PHONY: clean
clean:
	cargo clean
	rm -f ./built/*
