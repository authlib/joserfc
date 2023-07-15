lang=en

dev-docs:
	sphinx-build docs public/${lang}/dev -D language=${lang} -b dirhtml -a


build-docs:
	@sphinx-build docs build/${lang} -D language=${lang} -b dirhtml
	@rm build/${lang}/.buildinfo
	@rm -r build/${lang}/.doctrees


clean-docs:
	@rm -fr public/${lang}


coverage:
	@pytest --cov --cov-report=html
