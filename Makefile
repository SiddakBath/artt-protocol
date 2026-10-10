PYTHON ?= .venv/bin/python
OUTPUT ?= scratch/coding-demo

.PHONY: demo
demo:
	$(PYTHON) -m demos.coding_agent.run --output $(OUTPUT)
	$(PYTHON) -m demos.coding_agent.report --input $(OUTPUT) --html $(OUTPUT)/report.html
