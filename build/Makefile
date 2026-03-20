.PHONY: all clean test bank atm clean-files

all:
	@mkdir -p _build
	@cd _build && cmake .. -DCMAKE_BUILD_TYPE=Release
	@cd _build && $(MAKE) --no-print-directory
	@cp _build/bank _build/atm .

clean:
	@rm -rf _build bank atm test_validator test_crypto test_protocol atmdir bankdir
	@find . -type f \( -name '*.auth' -o -name '*.card' \) -exec rm -f {} +

clean-files:
	@find . -type f \( -name '*.auth' -o -name '*.card' \) -exec rm -f {} +

clean-bank:
	@rm -rf _build bank test_validator test_crypto test_protocol bankdir
	@find . -type f \( -name '*.auth' -o -name '*.card' \) -exec rm -f {} +

clean-atm:
	@rm -rf _build atm test_validator test_crypto test_protocol atmdir
	@find . -type f \( -name '*.auth' -o -name '*.card' \) -exec rm -f {} +

bank:
	$(MAKE) clean-bank
	$(MAKE)
	@rm -f atm bank
	@mkdir -p bankdir
	@cp _build/bank bankdir/bank

atm:
	$(MAKE) clean-atm
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
