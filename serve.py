from livereload import Server, shell

app = Server()
# app.watch("src", shell("make build-docs"), delay=2)
app.watch("docs/*.rst", shell("make dev-docs"), delay=2)
app.watch("docs/*/*.rst", shell("make dev-docs"), delay=2)
app.watch("docs/locales/zh/LC_MESSAGES/*.po", shell("make dev-docs -e lang=zh"), delay=2)
app.serve(root="build")
