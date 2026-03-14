# Thin wrapper Makefile for spec compliance
# Usage: cd build && make

.PHONY: all clean test

all:
	@mkdir -p _build
	@cd _build && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
	@cd _build && $(MAKE) --no-print-directory
	@mkdir -p atmdir bankdir
	@cp _build/atm atmdir/atm
	@cp _build/bank bankdir/bank

test: all
	@cd _build && $(MAKE) test_validator test_crypto test_protocol --no-print-directory
	@cp _build/test_validator _build/test_crypto _build/test_protocol .
	@echo "Running unit tests..."
	@./test_validator && ./test_crypto && ./test_protocol
	@echo ""
	@echo "Running integration tests..."
	@bash tests/test_integration.sh

clean:
	@rm -rf _build bank atm test_validator test_crypto test_protocol *.auth *.card atmdir bankdir

clean-file:
	@rm -f atmdir/*.auth bankdir/*.auth atmdir/*.card bankdir/*.card
