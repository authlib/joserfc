import os

project = "joserfc"
copyright = "Copyright &copy; 2023, Hsiaoming Yang"
author = "Hsiaoming Yang"
version = "v1"

language = os.getenv('DOC_LANG', 'en')

html_title = "JOSE"
html_baseurl = "https://jose.authlib.org/"

templates_path = ["_templates"]
html_static_path = ["_static"]
html_theme = "shibuya"

html_copy_source = False
html_show_sourcelink = False

html_additional_pages = {
    "index": "index.html",
}
