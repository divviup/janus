.ONESHELL:
.SHELL := /usr/bin/bash
BOLD=$(shell tput bold)
RED=$(shell tput setaf 1)
GREEN=$(shell tput setaf 2)
YELLOW=$(shell tput setaf 3)
RESET=$(shell tput sgr0)

ifeq ($(ENV),)
$(info $(BOLD)Example usage: \`ENV=demo make plan\`$(RESET))
$(error $(BOLD)$(RED)ENV was not set$(RESET))
endif

VARS="variables/$(ENV).tfvars"
STATE_BUCKET="$(shell grep '^state_bucket' $(VARS) | awk -F'=' '{print $$2}' | sed 's/[[:space:]]//g')"
TFSTATE_PATH="$(shell grep '^tfstate_path' $(VARS) | awk -F'=' '{print $$2}' | sed 's/[[:space:]]//g')"

ifeq ($(TFSTATE_PATH),"")
TFSTATE_PATH="local-cluster.tfstate"
endif

ifeq ($(STATE_BUCKET),"")
$(info $(BOLD)Using local main module with local storage in file $(TFSTATE_PATH)$(RESET))
TERRAFORM_CHDIR="main_local"
BACKEND_CONFIG="path=$(TFSTATE_PATH)"
else
$(info $(BOLD)Using GCP main module with backend storage in GCS bucket $(STATE_BUCKET)$(RESET))
TERRAFORM_CHDIR="main_gcp"
BACKEND_CONFIG="bucket=$(STATE_BUCKET)"
endif

$(info backend config $(BACKEND_CONFIG))

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: prep
prep: ## Configure the tfstate backend and update any modules
	@rm -f $(TERRAFORM_CHDIR)/.terraform/terraform.tfstate
	@if [ ! -f "$(VARS)" ]; then \
		echo "$(BOLD)$(RED)Could not find variables file: $(VARS)$(RESET)"; \
		exit 1; \
	 fi
	@echo "$(BOLD)Configuring the terraform backend$(RESET)"
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		init \
		-input=false \
		-force-copy \
		-upgrade \
		-backend=true \
		-backend-config=$(BACKEND_CONFIG)

.PHONY: validate
validate: prep ## Show what terraform believes about the validity of the defined resources
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		 validate

.PHONY: format
format: prep ## Rewrites all Terraform configuration files to a canonical format.
	@terraform fmt -recursive

.PHONY: plan
plan: prep ## Show what terraform thinks it will do
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		 plan \
		-lock=true \
		-input=false \
		-refresh=true \
		-var-file="../$(VARS)"

.PHONY: plan-destroy
plan-destroy: prep ## Creates a destruction plan.
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		 plan \
		-input=false \
		-refresh=true \
		-destroy \
		-var-file="../$(VARS)"

.PHONY: apply
apply: prep ## Have terraform do the things. This will cost money.
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		 apply \
		-lock=true \
		-input=false \
		-refresh=true \
		-var-file="../$(VARS)"

.PHONY: destroy
destroy: prep ## Destroy the things
	@terraform \
		-chdir=$(TERRAFORM_CHDIR) \
		 destroy \
		-lock=true \
		-input=false \
		-refresh=true \
		-var-file="../$(VARS)"
