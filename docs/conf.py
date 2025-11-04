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
    "custom.css",
]
html_theme = "shibuya"

html_copy_source = False
html_show_sourcelink = False

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_sitemap",
    "sphinx_contributors",
    "sphinx_iconify",
    "shibuya.sponsors",
]

iconify_script_url = ""
sponsors_json_url = "https://cdn.jsdelivr.net/gh/lepture/lepture/sponsors.json"

extlinks = {
    "user": ("https://github.com/%s", "@%s"),
    "pull": ("https://github.com/authlib/joserfc/pull/%s", "pull request #%s"),
    "issue": ("https://github.com/authlib/joserfc/issues/%s", "issue #%s"),
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_favicon = "_static/icon.svg"

html_theme_options = {
    "accent_color": "blue",
    "light_logo": "_static/light-logo.svg",
    "dark_logo": "_static/dark-logo.svg",
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
                {"title": "Authlib", "url": "https://authlib.org/", "summary": "OAuth, JOSE, OpenID, etc."},
                {"title": "JOSE RFC", "url": "https://jose.authlib.org/", "summary": "JWS, JWE, JWK, and JWT."},
                {
                    "title": "OTP Auth",
                    "url": "https://otp.authlib.org/",
                    "summary": "One time password, HOTP/TOTP.",
                },
            ],
        },
        {"title": "Support us", "url": "/en/sponsors"},
    ],
}

html_baseurl = "https://jose.authlib.org/en/"
html_context = {
    "source_type": "github",
    "source_user": "authlib",
    "source_repo": "joserfc",
    "source_docs_path": "/docs/",
}

# sitemap configuration
site_url = "https://jose.authlib.org/"
sitemap_url_scheme = "{lang}{link}"
sitemap_filename = "../sitemap.xml"
sitemap_locales = []


def setup(app):
    global language, html_baseurl, sitemap_filename, sitemap_locales

    language = app.config.language
    if language != "en":
        sitemap_filename = "sitemap.xml"
        sitemap_locales = [None]

    if language == "zh":
        nav_links = html_theme_options["nav_links"]
        nav_links[0]["title"] = "项目"
        nav_links[1]["title"] = "赞助我们"
        nav_links[1]["url"] = "/zh/sponsors"

    html_baseurl = f"https://jose.authlib.org/{language}/"
    html_context["languages"] = [
        ("English", "https://jose.authlib.org/en/%s/", "en"),
        ("简体中文", "https://jose.authlib.org/zh/%s/", "zh"),
    ]
