# Thin wrapper Makefile for spec compliance
# Usage: cd build && make

.PHONY: all clean test

all:
	@mkdir -p _build
	@cd _build && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
	@cd _build && $(MAKE) --no-print-directory
	@cp _build/bank _build/atm .

clean:
	@rm -rf _build bank atm *.auth *.card
