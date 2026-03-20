.PHONY: compile test dialyzer explorer tag clean help fmt fmt-check xref lint eunit check

compile: ## Build the project
	rebar3 compile

test: ## Run all unit tests
	rebar3 eunit --module ebl_compile_test,ebl_lexer_test,ebl_parser_test,ebl_typecheck_test,ebl_pre_verify_test,ebl_integration_test,ebl_cross_validate_test,ebl_packet_test,ebl_realworld_test,ebl_realworld2_test,ebl_prop_test,ebl_prop_xval_test,ebl_stateful_xval_test,ebl_ubpf_test,ebpf_codegen_test,ebpf_ctx_test,ebpf_endian_test,ebpf_insn_test,ebpf_ir_gen_test,ebpf_peephole_test,ebpf_pkt_xval_test,ebpf_regalloc_test,ebpf_test_pkt_test,ebpf_vm_test

eunit: ## Run unit tests
	rebar3 eunit --module ebl_compile_test,ebl_lexer_test,ebl_parser_test,ebl_typecheck_test,ebl_pre_verify_test,ebl_integration_test,ebl_cross_validate_test,ebl_packet_test,ebl_realworld_test,ebl_realworld2_test,ebl_prop_test,ebl_prop_xval_test,ebl_stateful_xval_test,ebl_ubpf_test,ebpf_codegen_test,ebpf_ctx_test,ebpf_endian_test,ebpf_insn_test,ebpf_ir_gen_test,ebpf_peephole_test,ebpf_pkt_xval_test,ebpf_regalloc_test,ebpf_test_pkt_test,ebpf_vm_test

# ── Quality ──────────────────────────────────────────────

fmt: ## Format code with erlfmt
	rebar3 fmt

fmt-check: ## Check formatting (CI)
	rebar3 fmt --check

xref: ## Cross-reference analysis
	rebar3 xref

dialyzer: ## Run Dialyzer static analysis
	rebar3 dialyzer

lint: fmt-check xref dialyzer ## All static checks

check: lint test ## CI gate: all checks + all tests

explorer: ## Start the compiler explorer on localhost:8080
	rebar3 shell --eval 'ebpf_debugger_web:start(8080).'

## Release ----------------------------------------------------------------

CURRENT_VERSION = $(shell grep -oP '(?<=\{vsn, ")[^"]+' src/erlkoenig_ebpf.app.src)
VERSION_FILES = src/erlkoenig_ebpf.app.src dsl/mix.exs

tag: ## Tag a release (main only): make tag VERSION=X.Y.Z
ifndef VERSION
	$(error Usage: make tag VERSION=X.Y.Z)
endif
	@if ! echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Error: VERSION must be semver (e.g., 0.2.0)" >&2; exit 1; \
	fi
	@BRANCH=$$(git branch --show-current); \
	if [ "$$BRANCH" != "main" ]; then \
		echo "Error: tags are only allowed from main (currently on $$BRANCH)" >&2; \
		echo "  git checkout main && git merge $$BRANCH && make tag VERSION=$(VERSION)" >&2; \
		exit 1; \
	fi
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working tree is dirty — commit or stash first" >&2; exit 1; \
	fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag v$(VERSION) already exists" >&2; exit 1; \
	fi
	@echo "Bumping version: $(CURRENT_VERSION) -> $(VERSION)"
	sed -i 's/{vsn, "[^"]*"}/{vsn, "$(VERSION)"}/' src/erlkoenig_ebpf.app.src
	sed -i 's/version: "[^"]*"/version: "$(VERSION)"/' dsl/mix.exs
	git add $(VERSION_FILES)
	git commit -m "chore: bump version to $(VERSION)"
	git tag -a "v$(VERSION)" -m "$(if $(MSG),$(MSG),v$(VERSION))"
	@echo ""
	@echo "Tagged v$(VERSION). Push with:"
	@echo "  git push origin main v$(VERSION)"

## Clean -------------------------------------------------------------------

clean: ## Remove build artifacts
	rebar3 clean

help: ## Show this help
	@echo "erlkoenig_bpf — eBPF Data Plane for erlkoenig"
	@echo ""
	@echo "Targets:"
	@awk -F ':|##' '/^[a-zA-Z_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$NF}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make compile          Build everything"
	@echo "  make test             Run all tests"
	@echo "  make explorer         Compiler explorer on :8080"
