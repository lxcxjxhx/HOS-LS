@echo off

type NUL && "%CODEQL_DIST%\codeql.exe" database index-files ^
    --prune=**/*.testproj ^
    --include-extension=.yml ^
    --include-extension=.yaml^
    --size-limit=5m ^
    --language=yaml ^
    --working-dir=. ^
    "%CODEQL_EXTRACTOR_YAML_WIP_DATABASE%"

exit /b %ERRORLEVEL%
