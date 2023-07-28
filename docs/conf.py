from joserfc import __version__

project = "joserfc"
copyright = "Copyright &copy; 2023, Hsiaoming Yang"
author = "Hsiaoming Yang"
version = __version__
release = __version__

language = "en"
locale_dirs = ["locales/"]

html_title = "joserfc"

html_static_path = ["_static"]
html_css_files = [
  'custom.css',
]
html_theme = "shibuya"

html_copy_source = False
html_show_sourcelink = False

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx_copybutton",
    "sphinx_design",
]

extlinks = {
    'user': ('https://github.com/%s', '@%s'),
    'pull': ('https://github.com/authlib/joserfc/pull/%s', 'pull request #%s'),
    'issue': ('https://github.com/authlib/joserfc/issues/%s', 'issue #%s'),
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_favicon = "_static/icon.svg"

html_theme_options = {
    "light_logo": "_static/light-logo.svg",
    "dark_logo": "_static/dark-logo.svg",
    "light_css_variables": {
        "--sy-rc-theme": "62,127,203",
    },
    "dark_css_variables": {
        "--sy-rc-theme": "102,173,255",
    },
    "twitter_site": "authlib",
    "twitter_creator": "lepture",
    "twitter_url": "https://twitter.com/authlib",
    "github_url": "https://github.com/authlib/joserfc",
    "discord_url": "https://discord.gg/HvBVAeNAaV",
    "carbon_ads_code": "CE7DKK3W",
    "carbon_ads_placement": "joseauthliborg",
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
                    "title": "JOSE RFC",
                    "url": "https://jose.authlib.org/",
                    "summary": "JWS, JWE, JWK, and JWT."
                },
                {
                    "title": "OTP Auth",
                    "url": "https://otp.authlib.org/",
                    "summary": "One time password, HOTP/TOTP.",
                },
            ]
        },
        {"title": "Sponsor me", "url": "https://github.com/sponsors/authlib"},
    ]
}

html_baseurl = "https://jose.authlib.org/en/dev/"
html_context = {
    "source_type": "github",
    "source_user": "authlib",
    "source_repo": "joserfc",
    "source_docs_path": "/docs/",
}

def setup(app):
    import os
    global language, html_baseurl

    language = app.config.language
    ref_name = os.getenv("REF_NAME")
    if ref_name and ref_name.startswith("1."):
        version_path = "v1"
    else:
        version_path = "dev"

    html_baseurl = f"https://jose.authlib.org/{language}/{version_path}/"
    html_context["languages"] = [
        ("English", f"/en/{version_path}/%s/", "en"),
        ("简体中文", f"/zh/{version_path}/%s/", "zh"),
    ]
