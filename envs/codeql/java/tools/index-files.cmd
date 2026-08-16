@echo off

IF NOT DEFINED CODEQL_EXTRACTOR_JAVA_STANDALONE_JAVA_CMD SET CODEQL_EXTRACTOR_JAVA_STANDALONE_JAVA_CMD=java

type NUL && "%CODEQL_EXTRACTOR_JAVA_STANDALONE_JAVA_CMD%" ^
  -cp "%CODEQL_EXTRACTOR_JAVA_ROOT%\tools\codeql-java-agent.jar;" ^
  com.semmle.extractor.java.Extractor ^
  %1 -d "%CODEQL_EXTRACTOR_JAVA_SCRATCH_DIR%\codeql-standalone-build-classes"

exit /b 0
