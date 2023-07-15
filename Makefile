lang=en

dev-docs:
	sphinx-build docs public/${lang}/dev -D language=${lang} -b dirhtml -a


build-docs:
	@rm -fr build
	@sphinx-build docs build/en -D language=en -b dirhtml
	@sphinx-build docs build/zh -D language=zh -b dirhtml
	@rm build/*/.buildinfo
	@rm -r build/*/.doctrees


clean-docs:
	@rm -fr public/${lang}


coverage:
	@pytest --cov --cov-report=html
