.PHONY: compile test dialyzer explorer clean help

compile: ## Build the project
	rebar3 compile

test: ## Run all unit tests
	rebar3 eunit --module ebl_compile_test,ebl_lexer_test,ebl_parser_test,ebl_typecheck_test,ebl_pre_verify_test,ebl_integration_test,ebl_cross_validate_test,ebl_packet_test,ebl_realworld_test,ebl_realworld2_test,ebl_prop_test,ebl_prop_xval_test,ebl_stateful_xval_test,ebl_ubpf_test,ebpf_codegen_test,ebpf_ctx_test,ebpf_endian_test,ebpf_insn_test,ebpf_ir_gen_test,ebpf_peephole_test,ebpf_pkt_xval_test,ebpf_regalloc_test,ebpf_test_pkt_test,ebpf_vm_test

dialyzer: ## Run Dialyzer static analysis
	rebar3 dialyzer

explorer: ## Start the compiler explorer on localhost:8080
	rebar3 shell --eval 'ebpf_debugger_web:start(8080).'

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
