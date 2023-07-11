build-docs:
	@sphinx-build docs/en public/en/dev -b dirhtml -a


clean-docs:
	@rm -fr public/en


coverage:
	@pytest --cov --cov-report=html
