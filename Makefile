
build-docs:
	@$(MAKE) -C docs dirhtml


clean-docs:
	@rm -fr docs/_build


serve-docs:
	@python -m http.server --directory docs/_build/dirhtml 5500
