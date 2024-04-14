lang=en

dev-docs:
	sphinx-build docs public/${lang} -D language=${lang} -b dirhtml -a


build-docs:
	@sphinx-build docs public/${lang} -D language=${lang} -b dirhtml
	@rm public/${lang}/.buildinfo
	@rm -r public/${lang}/.doctrees


clean-docs:
	@rm -fr public/${lang}


coverage:
	@pytest --cov --cov-report=html
