.PHONY: install test run demo inspect fmt go-build compose

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

run:
	aetherwall up --plane both --policy policies/default.yaml

demo: install
	aetherwall demo

inspect:
	aetherwall inspect examples/attacks/injection_worm.json

fmt:
	python -m pip install ruff >/dev/null 2>&1 || true
	ruff check src tests || true

go-build:
	cd cmd/dataplane && go build -o dataplane .

compose:
	docker compose up --build
