@echo off

IF [%LGTM_INDEX_XML_MODE%]==[] SET LGTM_INDEX_XML_MODE=default

IF [%LGTM_INDEX_XML_MODE%]==[default] (
call :checksizelimit
) ELSE IF [%LGTM_INDEX_XML_MODE%]==[byname] (
call :indexbyname
) ELSE IF [%LGTM_INDEX_XML_MODE%]==[smart] (
call :indexsmart
) ELSE IF [%LGTM_INDEX_XML_MODE%]==[all] (
call :indexall
)

IF %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

IF [%LGTM_INDEX_PROPERTIES_FILES%]==[] SET LGTM_INDEX_PROPERTIES_FILES=true

IF [%LGTM_INDEX_PROPERTIES_FILES%]==[true] ^
type NUL && "%CODEQL_DIST%\codeql" database index-files ^
    --include-extension=.properties ^
    --also-match-lgtm-index-filters ^
    --size-limit=5m ^
    --language properties ^
    -- ^
    "%CODEQL_EXTRACTOR_JAVA_WIP_DATABASE%"

exit /b %ERRORLEVEL%

goto :eof

:checksizelimit

type NUL && "%CODEQL_DIST%\codeql" resolve files ^
    --total-size-limit 50m ^
    --include-extension=.xml ^
    --include-extension=.wsdd ^
    --also-match-lgtm-index-filters ^
    . >nul: 2>nul:

IF [%errorlevel%]==[0] (
goto :indexall
) ELSE (
echo More than 50MB of XML files found: only files with well-known names ^(e.g. pom.xml^) will be extracted in order to save space. Set LGTM_INDEX_XML_MODE to override this behaviour.
goto :indexbyname
)

goto :eof

:indexbyname

type NUL && "%CODEQL_DIST%\codeql" database index-files ^
    --include "**/AndroidManifest.xml" ^
    --include "**/pom.xml" ^
    --include "**/struts.xml" ^
    --include "**/web.xml" ^
    --also-match-lgtm-index-filters ^
    --size-limit 10m ^
    --language xml ^
    -- ^
    "%CODEQL_EXTRACTOR_JAVA_WIP_DATABASE%"

goto :eof

:indexsmart

setlocal
SET "CODEQL_EXTRACTOR_XML_PRIMARY_TAGS=faceted-project project plugin idea-plugin beans struts web-app module ui:uiBinder persistence deployment undeployment"
type NUL && "%CODEQL_DIST%\codeql" database index-files ^
    --include-extension=.xml ^
    --include-extension=.wsdd ^
    --also-match-lgtm-index-filters ^
    --size-limit 10m ^
    --language xml ^
    -- ^
    "%CODEQL_EXTRACTOR_JAVA_WIP_DATABASE%"
endlocal

goto :eof

:indexall

type NUL && "%CODEQL_DIST%\codeql" database index-files ^
    --include-extension=.xml ^
    --include-extension=.wsdd ^
    --also-match-lgtm-index-filters ^
    --size-limit 10m ^
    --language xml ^
    -- ^
    "%CODEQL_EXTRACTOR_JAVA_WIP_DATABASE%"

goto :eof
