.PHONY: build clean

# Build sdist + wheel
build:
	python3 -m build

# Remove build artifacts
clean:
	rm -rf dist/ build/ src/*.egg-info
