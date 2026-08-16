-- Overview:
-- Each traced language contains a `tracing-config.lua` file that defines two functions:
-- GetCompatibleVersions() -> [versionNumbers]. This function returns a list of major versions that
--   are compatible with this `tracing-config.lua` file.
-- RegisterExtractorPack(languageId) -> [matchers]. This function is called at by
--   the Lua tracer runtime. It returns a list of matchers for this language.
--   A matcher is a  function of the form function(compilerName, compilerPath, compilerArguments, languageID) -> Table | nil.
--   The return value of a matcher is either `nil` (no match) or a table with the following keys:
--     `trace`: True if the processes created by the compiler (and extractor) should be traced for the current language
--     `invocation`: An extractor invocation (or nil, if no extractor is to be executed).
--                    Each invocation is a table with key `path` (absolute path to the executable)
--                    and key `arguments` XOR `transformedArguments` (see explanation below)
--     `order`: Indicates when to execute the extractor. Either `ORDER_BEFORE`, `ORDER_AFTER`, or `ORDER_REPLACE`.
--              `ORDER_BEFORE` executes the extractor before the compiler, `ORDER_AFTER` executes the compiler first,
--              and `ORDER_REPLACE` replaces the compiler process with the extractor. Note: Only one language
--              can replace the compiler process.
--   For convenience, the `CreatePatternMatcher` function is provided that deals with most of the low-level details
--   of creating matchers.
--
-- `compilerArguments` has the following structure:
-- {
--   "nativeArgumentPointer": Opaque pointer that can be used to create transformations of these command line arguments
--                        that are executed in C++. This is mostly necessary for Windows, where we want to
--                        prepend/append to the command line without parsing it
--   "argv": Posix-only, array of command line arguments passed to the compiler
--   "commandLineString": Windows-only, the string passed to CreateProcess*(), with the path to the compile removed (and converted to UTF-8).
--                  Can be parsed into an argv array using `NativeCommandLineToArgv`, but be warned, this is not
--                  a canonical interpretation of the command line.
-- }
-- The arguments for an extractor invocation have two possible shapes:
--   either, the invocation sets the key `transformedArguments` (like `BuildExtractorInvocation` does), which is a table with
--   the following keys:
--     `nativeArgumentPointer`: The same opaque pointer, copied from the compiler invocation
--     `prepend`: A list of arguments to prepend to the arguments from the compiler
--     `append`: A list of arguments to append to the arguments from the compiler
--   alternatively, it sets the key `arguments`, which is a table with the following keys:
--     `argv`: Posix-only: The command line arguments (without argv[0])
--     `commandLineString`: Windows-only: The command line string (without the leading path to the executable).
--                    This will be converted internally to UTF-16 before execution.
--
-- The user can specify an extra lua config file on the command line.
-- This is loaded after all enabled languages have been loaded. This file also needs to contain a `GetCompatibleVersions`
-- function, just like a regular tracing config.
-- Second, it is required to contain a function
-- RegisterExtraConfig() -> [{languageId -> [matchers]}], i.e. a function that returns a table
--   mapping language IDs to a list of matchers. For each language ID, these matchers will _overwrite_ the matchers
--   registered by that language.
-- Furthermore, this function has full access to the implementation details of `base.lua`. However, obviously
-- no guarantees about compatibility are made when accessing internal functions or state.
-- For convenience, the GetRegisteredMatchers(languageId) method returns the existing matchers registered to that language. 
--
-- If tracing is enabled for multiple languages, the languages are processed in lexicographical order of the language ID.
-- For each language, the matchers are processed in the order supplied, until the first matcher returns non-nil.
-- Then, matching for that language is stopped.
-- Matchers between different languages are not allowed to cooperate - each language is supposed to be independent
-- of the other possibly active languages.
-- There is one exception, though: If two languages specify `replace=true` for the same compiler invocation,
-- then matching for the second language is aborted without action. In this case, a log message is emitted.
--
-- The following API is provided by the C++ runtime:
-- Added in version 1.0.0
-- Log(loglevel: int, fmt: string, ...): Prints the formatted string to the log, if the global log level is greater or
--                                        equal than loglevel.
-- IsAbsolutePath(path: string): Returns true if the path is an absolute path, false otherwise. Delegates to std::filesystem::path::is_absolute().
-- IsSameFile(file1: string, file2: string): Returns true if both file names point at the same underlying file, false otherwise. Delegates to std::filesystem::equivalent().
-- LogLevel: Integer that contains the (read-only) log level
-- OperatingSystem: One of 'linux', 'windows' or 'osx'
-- Architecture: One of 'x86', 'x64' or 'arm64'
-- debugprint(...): Same as `print` in standard Lua, but should only be used for
--                  debugging as it clutters stdout, which can break build systems
-- Windows-only: NativeArgumentsToArgv(nativeArgumentPointer) -> argv array: Calls CommandLineToArgvW on the native command line string, converts the individual arguments to UTF-8, and returns an array of UTF-8 strings.
-- _ExtraTracingConfig: (internal) Path to an extra tracing-config.lua file to load.
-- _EnabledLanguages: (internal) A table of all enabled languages, providing the absolute path to the extractor pack for each language.
-- Added in version 1.0.0
function IsPosix() return OperatingSystem == 'linux' or OperatingSystem == 'osx' end

-- The version number of the configuration file format, in x.y.z format. Follows semantic versioning.
-- Added in version 1.0.0
CurrentVersion = '1.0.0'

-- Added in version 1.0.0
ORDER_BEFORE = "before"
ORDER_AFTER = "after"
ORDER_REPLACE = "replace"

-- PlatformDirectory is the internal directory name used for architecture-specific files
-- and executables.
-- added in version 1.0.0
if OperatingSystem == 'linux' then
    -- arm64 Linux stages tools under linux-arm64 (matches CODEQL_PLATFORM); x64 uses linux64
    PlatformDirectory = Architecture == 'arm64' and 'linux-arm64' or 'linux64'
elseif OperatingSystem == 'windows' then
    PlatformDirectory = 'win64'
elseif OperatingSystem == 'osx' then
    PlatformDirectory = 'osx64'
else
    error('Unknown operating system: ' .. OperatingSystem)
end

-- PathSep is the platform-specific path separator
-- Added in version 1.0.0
if IsPosix() then
    PathSep = '/'
elseif OperatingSystem == 'windows' then
    PathSep = '\\'
end

-- internal function
function _ParseVersionNumber(version)
    local major, minor, patch = version:match('^(%d+)%.(%d+)%.(%d+)$')
    if major == nil then return nil end
    return tonumber(major), tonumber(minor), tonumber(patch)
end

-- Matcher providing simple pattern matching - matches a Lua pattern against the compiler's exe name
-- Added in version 1.0.0
function MatchCompilerName(pattern, compilerName, _compilerPath,
                           _compilerArguments, _languageId)
    Log(100, 'Matching pattern %s against compiler with name %s', pattern,
        compilerName)
    local matched = compilerName:match(pattern) ~= nil
    Log(100, 'Match result: %s', tostring(matched))
    return matched
end

-- Matcher providing exact matching against the full path of the compiler
-- Added in version 1.0.0
function MatchPathExact(pattern, _compilerName, compilerPath,
                        _compilerArguments, _languageId)
    local matched = IsSameFile(pattern, compilerPath)
    Log(100, 'Matching pattern %s against compiler with path %s: result %s',
        pattern, compilerPath, tostring(result))
    return matched
end

-- internal global variable, mapping from language ID to a list of matcher functions.
_RegisteredMatchers = {}

-- internal function
function _DisableAllMatchers() _RegisteredMatchers = {} end

-- Returns all registered matchers for a given language ID
-- Added in version 1.0.0
function GetRegisteredMatchers(languageId)
    return _RegisteredMatchers[languageId]
end

-- Added in version 1.0.0
-- returns the relative path to the platform-specific tools directory
function GetPlatformToolsDirectory()
    return 'tools' .. PathSep .. PlatformDirectory .. PathSep
end

-- Returns the absolute path to an extractor executable
-- If `extractorPath` is a relative path, prepends the path to the languages
-- extractor pack directory.
-- If `extractorPath` is already an absolute path, does nothing.
-- Added in version 1.0.0
function AbsolutifyExtractorPath(languageID, extractorPath)
    if IsAbsolutePath(extractorPath) then
        return extractorPath
    else
        return _EnabledLanguages[languageID] .. PathSep .. extractorPath
    end
end

-- Builds an extractor invocation, given a compiler invocation.
-- The extractor is either an absolute path, or resolved in the extractor pack
-- directory.
-- The extractor receives the same command line as the compiler invocation.
-- This can be modified by setting `preprend` and `append`.
-- `languageID`: The lua language id of the extractor `extractorPath` is to be resolved in
-- `extractorPath`: Either an absolute path to an extractor, or a relative path inside the extractor pack `languageID`
-- `compilerPath`: The absolute path to the compiler
-- `compilerArguments`: The command line arguments of the compiler invocation
-- `prepend`: A list of strings to prepend to the command line. The string `%${compiler}` is replaced
--            by the absolute path to the compiler.
-- `append`: A list of strings to append to the command line. The same variable replacement as in `prepend` is performed.
-- Added in version 1.0.0
function BuildExtractorInvocation(languageID, extractorPath, compilerPath,
                                  compilerArguments, prepend, append)
    Log(1, "=== Intercepted call to %s ===", compilerPath);

    if extractorPath == nil then return nil end
    prepend = prepend or {}
    append = append or {}
    Log(2,
        'building extractor invocation for ' .. languageID .. ' and compiler ' ..
            compilerPath)
    local extractorPath = AbsolutifyExtractorPath(languageID, extractorPath)
    -- expands supported variables in the argument string for prepend/append functionality
    local expandArgumentVariables = function(arg)
        return (arg:gsub('%${compiler}', compilerPath)) -- don't return the second return value of gsub
    end
    local transformedArguments = {
        nativeArgumentPointer = compilerArguments['nativeArgumentPointer'],
        prepend = {},
        append = {}
    }
    for _, arg in ipairs(prepend) do
        table.insert(transformedArguments['prepend'],
                     expandArgumentVariables(arg))
    end
    for _, arg in ipairs(append) do
        table.insert(transformedArguments['append'],
                     expandArgumentVariables(arg))
    end
    return {path = extractorPath, transformedArguments = transformedArguments}
end

-- Creates a list of match functions that matches a (list of) pattern(s) against the compiler invocation.
-- It then creates an invocation of the extractor with the arguments of the compiler.
-- The match can be against the compiler name, path or arguments.
-- The matchers will be executed in the order supplied. For every language, the first matcher that matches
-- wins. Thus, the same language can never match twice.
-- `languageID`: The language id of the language for which the pattern matcher is being created.
-- `pattern` can either be a string (one pattern) or a list of patterns is matched against the compiler invocation.
-- `matchFunction`: If `MatchCompilerName`, `pattern` is interpreted as Lua pattern (https://www.lua.org/manual/5.1/manual.html#5.4.1)
--             and matched against the name of the compiler executable.
--             If `MatchPathExact`, `pattern` is tested for equality with the full on-disk path to the compiler.
--             It is also possible to provide your own match_fn, the interface is
--             function(Pattern, CompilerName, CompilerPath, Arguments) -> Boolean
-- `extractorPath` is the name of the extractor executable. If not a full path to an executable, it is resolved in
--                  the extractor pack directory. If it is nil, don't execute an extractor for this match.
-- `options`: A table of additional options that specify how the compiler invocation is processed.
--            If 'trace' is set to false, the process subtree of the extractor invocation is not traced.
--            If 'trace' is set to true, all processes created by the compiler and the extractor (but not the extractor itself) are traced.
--            If 'replace' is set to true, the compiler process is aborted before the compiler runs.
--            This can be used, for example, to change the arguments to the compiler process if the 'extractor' being
--            run is the compiler again.
--            If 'preprend' is a list, all entries will be prepended to the `arguments` of the extractor invocation.
--            If 'append' is a list, all entries will be appended to the `arguments` of the extractor invocation.
-- Added in version 1.0.0
function CreatePatternMatcher(pattern, matchFunction, extractorPath, options)
    if type(pattern) == 'string' then
        pattern = {pattern}
    elseif type(pattern) ~= 'table' then
        Log(1, 'Pattern needs to be either of type string or table!')
        return nil
    end
    return function(compilerName, compilerPath, compilerArguments, languageID)
        for _, p in ipairs(pattern) do
            if matchFunction(p, compilerName, compilerPath, compilerArguments) then
                return {
                    trace = options['trace'],
                    jvmPrependArgs = options['jvmPrependArgs'],
                    order = options['order'],
                    invocation = BuildExtractorInvocation(languageID,
                                                          extractorPath,
                                                          compilerPath,
                                                          compilerArguments,
                                                          options['prepend'],
                                                          options['append'])
                }
            end
        end
        return nil -- indicates no match
    end
end

-- Quote command line arguments.
-- Added in version 1.0.0
function ArgvToCommandLineString(args)
    local function requiresQuoting(s)
        return s ~= '' or string.find(s, "[ \t\n\v\"]")
    end

    local function insertMany(t, c, n)
        for i = 1, n do
            table.insert(t, c)
        end
    end

    -- This implementation is based on
    -- https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
    function QuoteArgument(argument)

        if not requiresQuoting(argument) then
            return argument
        end

        local quoted = {'"'}
        local i = 0
        while true do
            i = i + 1
            local numberOfBackslashes = 0

            while i ~= #argument + 1 and argument:sub(i,i) == '\\' do
                i = i + 1
                numberOfBackslashes = numberOfBackslashes + 1
            end

            if i == #argument + 1 then
                insertMany(quoted, '\\', 2 * numberOfBackslashes)
                break
            end

            local c = argument:sub(i,i)
            if c == '"' then
                insertMany(quoted, '\\', 2 * numberOfBackslashes + 1)
            else
                insertMany(quoted, '\\', numberOfBackslashes)
            end

            table.insert(quoted, c)
        end

        table.insert(quoted, '"')
        return table.concat(quoted)
    end

    local arguments = {}
    -- Quote arguments if needed
    for _, arg in ipairs(args) do
      table.insert(arguments, QuoteArgument(arg))
    end
    return table.concat(arguments, " ")
end

-- internal: Checks whether the passed in extractor pack is compatible with the current
-- version of the configuration file format
function _CheckExtractorPackVersion(id, getCompatibleVersionFun)

    -- Check version compatibility
    -- abort loading a language pack that does not declare GetCompatibleVersions
    if not getCompatibleVersionFun then
        Log(1, 'Error: language %s does not define GetCompatibleVersions.', id)
        return false
    end
    local compatibleVersions = getCompatibleVersionFun()
    if compatibleVersions == nil then
        Log(1,
            'Error: extractor pack for %s does not return version numbers from GetCompatibleVersions.',
            id)
        return false
    end

    local curVerMaj, curVerMin, curVerPatch =
        _ParseVersionNumber(CurrentVersion)
    local foundCompatibleVersion = false
    for _, version in ipairs(compatibleVersions) do
        local verMaj, verMin, verPatch = _ParseVersionNumber(version)
        if verMaj == nil then
            Log(1,
                'Error: language %s returned %s which is not a valid version number from GetCompatibleVersions.',
                id, version)
            return false
        end
        -- Versions are only compatible if the current major version matches the required major version
        if verMaj == curVerMaj then
            -- either, the same minor version is required than we have (then check for patch level compatibility)
            if verMin == curVerMin then
                if verPatch <= curVerPatch then
                    foundCompatibleVersion = true
                end
                -- or the minor version required is lower than the current version, so we're compatible
            elseif verMin < curVerMin then
                foundCompatibleVersion = true
            end
        end
        Log(15,
            'Language %s version %s is compatible with current version %s: %s',
            id, version, CurrentVersion, foundCompatibleVersion)
    end
    if not foundCompatibleVersion then
        Log(1,
            'Config for language %s is incompatible with CurrentVersion: %s, skip loading language pack.',
            id, CurrentVersion)
        return false
    end
    return true
end

-- Load the tracing configs for all enabled extractors
-- internal function
function _LoadTracingConfigs()
    Log(50, 'Loading tracing configuration for all enabled languages')

    for id, path in pairs(_EnabledLanguages) do
        local tracing_config_path = path .. PathSep .. 'tools' .. PathSep ..
                                        'tracing-config.lua'
        Log(15, 'Loading config file for %s from path %s', id,
            tracing_config_path)
        local extractorConfig, error = loadfile(tracing_config_path)
        if extractorConfig == nil then
            Log(1,
                'Failed to load tracing config file for language %s and path %s with message %s',
                id, tracing_config_path, error)
            goto continue -- Lua doesn't have a continue statement
        end
        -- no access to any global functions (except for debugging) for the file-level function in the extractor config file
        local extractorConfigEnv = {
            debugprint = debugprint,
            Log = Log,
            LogLevel = LogLevel,
            CurrentVersion = CurrentVersion
        }
        setfenv(extractorConfig, extractorConfigEnv)
        -- this defines the two required top-level functions for an extractor pack
        -- - RegisterExtractorPack() and GetCompatibleVersions() - in `extractor_config_env`
        extractorConfig()

        -- Check version compatibility
        -- abort loading a language pack that does not declare GetCompatibleVersions
        if not _CheckExtractorPackVersion(id,
                                          extractorConfigEnv.GetCompatibleVersions) then
            goto continue
        end

        local registerExtractorPackAllowlist = {
            string = string,
            table = table,
            ipairs = ipairs,
            pairs = pairs,
            type = type,
            Log = Log,
            LogLevel = LogLevel,
            OperatingSystem = OperatingSystem,
            Architecture = Architecture,
            PlatformDirectory = PlatformDirectory,
            PathSep = PathSep,
            CurrentVersion = CurrentVersion,
            debugprint = debugprint,
            CreatePatternMatcher = CreatePatternMatcher,
            BuildExtractorInvocation = BuildExtractorInvocation,
            MatchCompilerName = MatchCompilerName,
            MatchPathExact = MatchPathExact,
            AbsolutifyExtractorPath = AbsolutifyExtractorPath,
            GetRegisteredMatchers = GetRegisteredMatchers,
            GetPlatformToolsDirectory = GetPlatformToolsDirectory,
            NativeArgumentsToArgv = NativeArgumentsToArgv,
            ArgvToCommandLineString = ArgvToCommandLineString,
            ORDER_BEFORE = ORDER_BEFORE,
            ORDER_AFTER = ORDER_AFTER,
            ORDER_REPLACE = ORDER_REPLACE
        }
        -- add the functions defined in the extractor pack to the allow-list
        for fn, ptr in pairs(extractorConfigEnv) do
            registerExtractorPackAllowlist[fn] = ptr
        end
        setfenv(extractorConfigEnv.RegisterExtractorPack,
                registerExtractorPackAllowlist)
        local matchers = extractorConfigEnv.RegisterExtractorPack(id)
        if matchers ~= nil then
            _RegisteredMatchers[id] = matchers
        else
            Log(1,
                "RegisterExtractorPack for language %s did not return any matchers.")
        end

        ::continue::
    end
    Log(100, "_ExtraTracingConfig set to: %s", _ExtraTracingConfig)
    if _ExtraTracingConfig then
        Log(1, "Loading extra tracing config %s", _ExtraTracingConfig)
        -- load the extra tracing config
        local extraTracingConfig, error = loadfile(_ExtraTracingConfig)
        if extraTracingConfig == nil then
            Log(1,
                'Failed to load extra tracing config file %s with message %s',
                _ExtraTracingConfig, error)
            -- alert the user to the error, by disabling tracing entirely
            _DisableAllMatchers()
            return
        end
        -- we execute this in the global context, as well as GetCompatibleVersions(), so
        -- that this can really do everything (unlike the real language packs which are more limited)
        extraTracingConfig()
        if not _CheckExtractorPackVersion('extra-config-file',
                                          GetCompatibleVersions) then
            -- alert the user to the error, by disabling tracing entirely
            _DisableAllMatchers()
            return
        end
        -- invoke the extra tracing config in the full global environment,
        -- so that it has access to all the internals.
        -- this function can be omitted
        if RegisterExtraConfig then
            local matcherOverwrites = RegisterExtraConfig()
            if matcherOverwrites ~= nil then
                for id, matchers in pairs(matcherOverwrites) do
                    Log(100, "Overwriting matchers for language %s", id)
                    _RegisteredMatchers[id] = matchers
                end
            end
        end
    end
end

-- internal function
-- The layout of `compilerArguments` is documented at the top of the file
function _ExecuteMatchers(compilerName, compilerPath, compilerArguments)
    local languageIDs = {}
    for id, _ in pairs(_EnabledLanguages) do table.insert(languageIDs, id) end
    table.sort(languageIDs)
    -- if this is nil, run the compiler process unmodified.
    -- if this is set to an invocation, replace the compiler process with the specified invocation
    local compilerReplacement = nil
    local preInvocations = {} -- extractor invocations before the compiler
    local postInvocations = {} -- extractor invocations after the compiler
    local traceLanguages = {} -- the list of languages for which tracing is enabled
    local jvmPrependArgs = nil
    for _, id in ipairs(languageIDs) do
        local traceThisLanguage = true
        Log(20, 'Execute matcher for language %s', id)
        local matchers = GetRegisteredMatchers(id)
        if matchers then
            for _, matcher in ipairs(matchers) do
                local match = matcher(compilerName, compilerPath,
                                      compilerArguments, id)
                if match then
                    if match.order == ORDER_REPLACE then
                        if compilerReplacement == nil then
                            -- The first match with `order = ORDER_REPLACE` gets to overwrite the compiler
                            compilerReplacement = match.invocation
                            Log(2, 'Replacing the compiler process...')
                        elseif compilerReplacement ~= nil then
                            -- The next matches that _also_ want to replace the compiler get aborted early,
                            -- as they might launch a process that is incompatible with the process spawned by the first match.
                            -- For example, when inserting command line arguments into a build process,
                            -- the invocation often contains the original process with `replace = yes`.
                            -- In this case, we want to guard against spawning that modified process twice.
                            Log(1,
                                'Warning: Cancelling invocations for language id %s and a successful match against %s, as conflicting replace behaviour was detected.',
                                id, compilerName)
                            break -- abort matching for this language
                        end
                    elseif match.order == ORDER_BEFORE then
                        table.insert(preInvocations, match.invocation)
                    elseif match.order == ORDER_AFTER then
                        table.insert(postInvocations, match.invocation)
                    else
                        if match.invocation ~= nil then
                            Log(1, "Unknown order " .. match.order)
                        end
                    end

                    if match.jvmPrependArgs then
                        if jvmPrependArgs == nil then
                            -- We need to quote the argument in a way that will be understood by `parse_args` in
                            -- our libtrace_jvm.cpp (which mimics `Arguments::parse_options_environment_variable`
                            -- in openjdk/hotspot/src/share/vm/runtime/arguments.cpp). This generally recognises
                            -- strings enclosed by `"` or `'`, with no way of escaping those quotes other than
                            -- ending one quoted string part and starting another.
                            --
                            -- We transform the arguments by enclosing each argument with single quotes, after
                            -- replacing any single quotes within the argument itself by the sequence `'"'"'`
                            -- -- that is, "terminate single-quoted string, start double-quoted string, insert
                            -- a single-quote, terminate double-quoted string, start single-quoted string".
                            jvmPrependArgs = ''
                            for _, arg in ipairs(match.jvmPrependArgs) do
                                jvmPrependArgs =
                                    jvmPrependArgs .. "'" ..
                                        arg:gsub("'", "'\"'\"'") .. "' "
                            end
                        else
                            Log(1,
                                'At this time, only one matcher is allowed to set jvmPrependArgs!')
                            break -- abort matching for this language
                        end
                    end
                    if match.trace == false then
                        Log(1, "Disabling tracing for language %s.", id)
                        traceThisLanguage = false
                    end
                    break -- only the first successful match per language gets executed
                end
            end
        else
            Log(2, 'No matchers to execute for %s', id)
        end
        if traceThisLanguage then table.insert(traceLanguages, id) end
    end
    if #postInvocations > 0 and compilerReplacement ~= nil then
        Log(1,
            'Warning: postInvocations and compilerReplacement are mutually exclusive!')
        Log(1, 'postInvocations will be ignored.')
        postInvocations = {}
    end
    return {
        preInvocations = preInvocations,
        compilerReplacement = compilerReplacement,
        postInvocations = postInvocations,
        traceLanguages = traceLanguages,
        jvmPrependArgs = jvmPrependArgs
    }
end

-- internal function, only to be called from the C++ code
function _EntryPoint(compilerName, compilerPath, compilerArguments)
    _LoadTracingConfigs()
    return _ExecuteMatchers(compilerName, compilerPath, compilerArguments)
end
