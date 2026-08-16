function RegisterExtractorPack(id)
    local pathToAgent = AbsolutifyExtractorPath(id, 'tools' .. PathSep ..
                                                    'codeql-java-agent.jar')
    -- inject our CodeQL agent into all processes that boot a JVM
    return {
        CreatePatternMatcher({'.'}, MatchCompilerName, nil, {
            jvmPrependArgs = {
                '-javaagent:' .. pathToAgent .. '=ignore-project,java,kotlin',
                '-Xbootclasspath/a:' .. pathToAgent
            }
        })
    }
end

-- Return a list of minimum supported versions of the configuration file format
-- return one entry per supported major version.
function GetCompatibleVersions() return {'1.0.0'} end
