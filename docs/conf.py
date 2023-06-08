project = "joserfc"
copyright = "Copyright &copy; 2023, Hsiaoming Yang"
author = "Hsiaoming Yang"
version = "v1"

language = "en"

html_title = "JOSE"
html_baseurl = "https://jose.authlib.org/"

templates_path = ["_templates"]
html_static_path = ["_static"]
html_theme = "shibuya"

html_copy_source = False
html_show_sourcelink = False

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
    "sphinx_design",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_theme_options = {
    "twitter_site": "authlib",
    "twitter_creator": "lepture",
    "twitter_url": "https://twitter.com/authlib",
    "github_url": "https://github.com/authlib/joserfc",

    "nav_links": [
        {
            "title": "Projects",
            "children": [
                {
                    "title": "Authlib",
                    "url": "https://authlib.org/",
                    "summary": "OAuth, JOSE, OpenID, etc."
                },
                {
                    "title": "OTP Auth",
                    "url": "https://otp.authlib.org/",
                    "summary": "One time password, HOTP/TOTP.",
                },
            ]
        },
        {"title": "Sponsor me", "url": "https://github.com/sponsors/lepture"}
    ]
}
