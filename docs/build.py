import os
import json
import pathlib
import subprocess

latest = "dev"
baseurl = "https://jose.authlib.org"
root_path = pathlib.Path(__file__).parent


def generate_additional_conf(language: str):
    ref_type = os.getenv("REF_TYPE")
    ref_name = os.getenv("REF_NAME")
    if ref_type == "tag":
        version_path = ".".join(ref_name.split(".")[:2])
    else:
        version_path = latest

    conf = (
        f'html_baseurl = "{baseurl}/{language}/{version_path}/"\n\n'
    )

    repo = os.getenv("REPOSITORY")
    source_user, source_repo = repo.split("/")
    source_docs_path = f"/docs/{language}/"
    html_context = {
        "source_type": "github",
        "source_user": source_user,
        "source_repo": source_repo,
        "source_docs_path": source_docs_path,
    }
    conf += "html_context = " + json.dumps(html_context, indent=4)
    return conf


def update_conf(language: str):
    conf = "\n\n# auto generated conf\n\n" + generate_additional_conf(language)
    print(conf)
    with open(root_path / language / "conf.py", "a") as f:
        f.write(conf)


def sphinx_build(language: str):
    docs_path = (root_path / language).resolve()
    update_conf(language)
    cmd = ["sphinx-build", "-b", "dirhtml", docs_path, f"build/{language}"]
    subprocess.run(cmd)


sphinx_build("en")
