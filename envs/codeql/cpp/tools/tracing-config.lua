function RegisterExtractorPack(id)
    local cppExtractor = GetPlatformToolsDirectory() .. 'extractor'
    if OperatingSystem == 'windows' then
        cppExtractor = cppExtractor .. '.exe'
    end
    local windowsPatterns = {
        CreatePatternMatcher({
            '^cl%.exe$', '^clang%-cl%.exe$', '^.*clang.*%.exe$',
            '^.*cc.*%.exe$', '^.*%+%+.*%.exe$', '^c51%.exe$', '^cx51%.exe$'
        }, MatchCompilerName, cppExtractor, {
            prepend = {'--mimic', '"${compiler}"'},
            order = ORDER_AFTER
        }),
        CreatePatternMatcher(
            {'^collect2%.exe$', '^ld.*%.exe$', '^.*%-ld.*%.exe$'},
            MatchCompilerName, cppExtractor, {
                prepend = {
                    '--linker', '--semmle-linker-executable', '"${compiler}"'
                },
                order = ORDER_AFTER
            }),
        CreatePatternMatcher({'^link%.exe$', '^lld%-link%.exe$'},
                             MatchCompilerName, cppExtractor, {
            prepend = {
                '--ms-linker', '--semmle-linker-executable', '"${compiler}"'
            },
            order = ORDER_AFTER
        }),
        CreatePatternMatcher({'^as%.exe$', '^.*%-as%.exe$'}, MatchCompilerName,
                             cppExtractor, {
            prepend = {
                '--assembler', '--codeql-assembler-executable', '"${compiler}"'
            },
            order = ORDER_AFTER
        }),
        CreatePatternMatcher({'^.*armlink.exe$'}, MatchCompilerName, cppExtractor, {
            prepend = {
                '--arm-linker', '--semmle-linker-executable', '${compiler}'
            },
            order = ORDER_AFTER
        }),
    }
    local posixPatterns = {
        CreatePatternMatcher({'^configure$', '^do%-prebuild$'},
                             MatchCompilerName, nil, {trace = false}),
        CreatePatternMatcher({'^collect2$', '^ld.*$', '^.*%-ld.*$', '^lld.*$'},
                             MatchCompilerName, cppExtractor, {
            prepend = {'--linker', '--semmle-linker-executable', '${compiler}'},
            order = ORDER_AFTER
        }),
        CreatePatternMatcher({'^as$', '^.*%-as$'}, MatchCompilerName,
                             cppExtractor, {
            prepend = {
                '--assembler', '--codeql-assembler-executable', '${compiler}'
            },
            order = ORDER_AFTER
        }),
        CreatePatternMatcher({'^.*armlink$'}, MatchCompilerName, cppExtractor, {
            prepend = {
                '--arm-linker', '--semmle-linker-executable', '${compiler}'
            },
            order = ORDER_AFTER
        }),
        -- Replaces the qcc/q++ compiler invocation, adding -nopipe to the compiler flags.
        function(compilerName, compilerPath, compilerArguments, _languageId)
            if MatchCompilerName('^qcc$', compilerName, compilerPath,
                                 compilerArguments) or
                MatchCompilerName('^q++$', compilerName, compilerPath,
                                  compilerArguments) then
                return {
                    order = ORDER_REPLACE,
                    invocation = BuildExtractorInvocation(_languageId,
                                                          compilerPath,
                                                          compilerPath,
                                                          compilerArguments,
                                                          {'-nopipe'}, nil)
                }
            end
        end,
        CreatePatternMatcher({'^.*clang.*$', '^.*cc.*$', '^.*%+%+.*$', '^icpc$'},
                             MatchCompilerName, cppExtractor, {
            prepend = {'--mimic', '${compiler}'},
            order = ORDER_AFTER
        }),
    }
    if OperatingSystem == 'windows' then
        return windowsPatterns
    else
        return posixPatterns
    end
end

-- Return a list of minimum supported versions of the configuration file format
-- return one entry per supported major version.
function GetCompatibleVersions() return {'1.0.0'} end
