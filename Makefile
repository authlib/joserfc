build-docs:
	@sphinx-build docs/en build/_html -b dirhtml -a


clean-docs:
	@rm -fr build/_html


coverage:
	@pytest --cov --cov-report=html
