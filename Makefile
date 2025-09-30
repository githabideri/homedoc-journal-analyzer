.PHONY: install run build clean

install:
	pip install -U pip build
	pip install -e .

run:
	python homedoc_journal_analyzer.py --help

build:
	python -m build

clean:
	rm -rf dist build *.egg-info
