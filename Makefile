# slack-deploy. Run `make` for the list.
PY    := venv/bin/python
HOST  ?= 127.0.0.1
PORT  ?= 8080
STAMP := venv/.installed

.PHONY: help setup init doctor bot web test backup migrate rekey sync cred-gen cred-list clean

help:
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t18

setup: $(STAMP)  ## create ./venv and install requirements

$(STAMP): requirements.txt
	python3 -m venv venv
	venv/bin/pip install --quiet --upgrade pip
	venv/bin/pip install --quiet -r requirements.txt
	@$(PY) -c "from sqlcipher3 import dbapi2" && touch $(STAMP)
	@echo "venv ready: $$($(PY) -V). Next: make init"

init: setup  ## create data/, both databases and the first admin user
	$(PY) manage.py init

doctor: setup  ## check ownership and permissions (exit 1 if any finding)
	$(PY) manage.py doctor

bot: setup  ## run the slack daemon (prompts for the global password)
	$(PY) manage.py bot

web: setup  ## run the web interface (HOST=, PORT= to override)
	$(PY) manage.py web --host $(HOST) --port $(PORT)

migrate: setup  ## apply pending migrations to deploy.db
	$(PY) manage.py migrate

rekey: setup  ## change the global password (also upgrades KDF params)
	$(PY) manage.py rekey

backup: setup  ## write today's backup zip and prune old ones
	$(PY) manage.py backup

test: setup  ## run the smoke checks
	$(PY) tests/test_smoke.py

clean:  ## remove ./venv (leaves data/ alone)
	rm -rf venv

sync: setup  ## clone or fast-forward every project checkout
	$(PY) manage.py sync

cred-gen: setup  ## generate an ssh key: make cred-gen NAME=deploy-key
	$(PY) manage.py cred-gen $(NAME)

cred-list: setup  ## list stored credentials
	$(PY) manage.py cred-list
