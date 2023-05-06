.PHONY: build-ebpf-debug build-ebpf-release debug release clean build

build-ebpf-debug:
	@./build-ebpf.sh

build-ebpf-release:
	@./build-ebpf.sh --release

debug: build-ebpf-debug
	@cargo build

release: build-ebpf-release
	@cargo build --release

clean:
	@cargo clean
