# Thin wrapper Makefile for spec compliance
# Usage: cd build && make

.PHONY: all clean test bank atm clean-files

all:
	@mkdir -p _build
	@cd _build && cmake .. -DCMAKE_BUILD_TYPE=Release
	@cd _build && $(MAKE) --no-print-directory
	@cp _build/bank _build/atm .

clean:
	@rm -rf _build bank atm test_validator test_crypto test_protocol **/*.auth **/*.card atmdir bankdir

clean-files:
	@rm -f **/*.auth **/*.card

bank:
	$(MAKE) clean
	$(MAKE)
	@rm -f atm bank
	@mkdir -p bankdir
	@cp _build/bank bankdir/bank

atm:
	$(MAKE) clean
	$(MAKE)
	@rm -f atm bank
	@mkdir -p atmdir
	@cp _build/atm atmdir/atm

test: all
	@cd _build && $(MAKE) test_validator test_crypto test_protocol --no-print-directory
	@cp _build/test_validator _build/test_crypto _build/test_protocol .
	@echo "Running unit tests..."
	@./test_validator && ./test_crypto && ./test_protocol
	@echo ""
	@echo "Running integration tests..."
	@bash tests/test_integration.sh
