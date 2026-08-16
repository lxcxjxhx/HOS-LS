"use strict";
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
var pathlib = require("path");
var readline = require("readline");
var ts = require("./typescript");
var ast_extractor = require("./ast_extractor");
var virtual_source_root_1 = require("./virtual_source_root");
Error.stackTraceLimit = Infinity;
var State = (function () {
    function State() {
        this.project = null;
        this.pendingFiles = [];
        this.pendingFileIndex = 0;
        this.pendingResponse = null;
        this.parsedPackageJson = new Map();
        this.packageTypings = new Map();
        this.enclosingPackageJson = new Map();
    }
    return State;
}());
var state = new State();
var reloadMemoryThresholdMb = getEnvironmentVariable("SEMMLE_TYPESCRIPT_MEMORY_THRESHOLD", Number, 1000);
function getPackageJson(file) {
    var cache = state.parsedPackageJson;
    if (cache.has(file))
        return cache.get(file);
    var result = getPackageJsonRaw(file);
    cache.set(file, result);
    return result;
}
function getPackageJsonRaw(file) {
    if (!ts.sys.fileExists(file))
        return undefined;
    try {
        var json = JSON.parse(ts.sys.readFile(file));
        if (typeof json !== 'object')
            return undefined;
        return json;
    }
    catch (e) {
        return undefined;
    }
}
function getPackageTypings(file) {
    var cache = state.packageTypings;
    if (cache.has(file))
        return cache.get(file);
    var result = getPackageTypingsRaw(file);
    cache.set(file, result);
    return result;
}
function getPackageTypingsRaw(packageJsonFile) {
    var json = getPackageJson(packageJsonFile);
    if (json == null)
        return undefined;
    var typings = json.types || json.typings;
    if (typeof typings !== 'string')
        return undefined;
    var absolutePath = pathlib.join(pathlib.dirname(packageJsonFile), typings);
    if (ts.sys.directoryExists(absolutePath)) {
        absolutePath = pathlib.join(absolutePath, 'index.d.ts');
    }
    else if (!absolutePath.endsWith('.ts')) {
        absolutePath += '.d.ts';
    }
    if (!ts.sys.fileExists(absolutePath))
        return undefined;
    return ts.sys.resolvePath(absolutePath);
}
function getEnclosingPackageJson(file) {
    var cache = state.packageTypings;
    if (cache.has(file))
        return cache.get(file);
    var result = getEnclosingPackageJsonRaw(file);
    cache.set(file, result);
    return result;
}
function getEnclosingPackageJsonRaw(file) {
    var packageJson = pathlib.join(file, 'package.json');
    if (ts.sys.fileExists(packageJson)) {
        return packageJson;
    }
    if (pathlib.basename(file) === 'node_modules') {
        return undefined;
    }
    var dirname = pathlib.dirname(file);
    if (dirname.length < file.length) {
        return getEnclosingPackageJson(dirname);
    }
    return undefined;
}
function checkCycle(root) {
    var path = [];
    function visit(obj) {
        if (obj == null || typeof obj !== "object")
            return false;
        if (obj.$cycle_visiting) {
            return true;
        }
        obj.$cycle_visiting = true;
        for (var k in obj) {
            if (!obj.hasOwnProperty(k))
                continue;
            if (+k !== +k && !astPropertySet.has(k))
                continue;
            if (k === "$cycle_visiting")
                continue;
            var cycle = visit(obj[k]);
            if (cycle) {
                path.push(k);
                return true;
            }
        }
        obj.$cycle_visiting = undefined;
        return false;
    }
    visit(root);
    if (path.length > 0) {
        path.reverse();
        console.log(JSON.stringify({ type: "error", message: "Cycle = " + path.join(".") }));
    }
}
var astProperties = [
    "$declarationKind",
    "$end",
    "$lineStarts",
    "$overloadIndex",
    "$pos",
    "$tokens",
    "argument",
    "argumentExpression",
    "arguments",
    "assertsModifier",
    "asteriskToken",
    "attributes",
    "block",
    "body",
    "caseBlock",
    "catchClause",
    "checkType",
    "children",
    "clauses",
    "closingElement",
    "closingFragment",
    "condition",
    "constraint",
    "constructor",
    "declarationList",
    "declarations",
    "default",
    "delete",
    "dotDotDotToken",
    "elements",
    "elementType",
    "elementTypes",
    "elseStatement",
    "escapedText",
    "exclamationToken",
    "exportClause",
    "expression",
    "exprName",
    "extendsType",
    "falseType",
    "finallyBlock",
    "flags",
    "head",
    "heritageClauses",
    "importClause",
    "incrementor",
    "indexType",
    "init",
    "initializer",
    "isExportEquals",
    "isTypeOf",
    "isTypeOnly",
    "keywordToken",
    "kind",
    "label",
    "left",
    "literal",
    "members",
    "messageText",
    "modifiers",
    "moduleReference",
    "moduleSpecifier",
    "name",
    "namedBindings",
    "objectType",
    "openingElement",
    "openingFragment",
    "operand",
    "operator",
    "operatorToken",
    "parameterName",
    "parameters",
    "parseDiagnostics",
    "phaseModifier",
    "properties",
    "propertyName",
    "qualifier",
    "questionDotToken",
    "questionToken",
    "right",
    "selfClosing",
    "statement",
    "statements",
    "tag",
    "tagName",
    "template",
    "templateSpans",
    "text",
    "thenStatement",
    "token",
    "tokenPos",
    "trueType",
    "tryBlock",
    "type",
    "typeArguments",
    "typeName",
    "typeParameter",
    "typeParameters",
    "types",
    "variableDeclaration",
    "whenFalse",
    "whenTrue",
];
var astMetaProperties = [
    "ast",
    "type",
];
var astPropertySet = new Set(__spreadArray(__spreadArray([], astProperties, true), astMetaProperties, true));
function stringifyAST(obj) {
    return JSON.stringify(obj, function (k, v) {
        return (+k === +k || astPropertySet.has(k)) ? v : undefined;
    });
}
function extractFile(filename) {
    var ast = getAstForFile(filename);
    return stringifyAST({
        type: "ast",
        ast: ast,
    });
}
function prepareNextFile() {
    if (state.pendingResponse != null)
        return;
    if (state.pendingFileIndex < state.pendingFiles.length) {
        checkMemoryUsage();
        var nextFilename = state.pendingFiles[state.pendingFileIndex];
        state.pendingResponse = extractFile(nextFilename);
    }
}
function handleParseCommand(command, checkPending) {
    if (checkPending === void 0) { checkPending = true; }
    var filename = command.filename;
    var expectedFilename = state.pendingFiles[state.pendingFileIndex];
    if (expectedFilename !== filename && checkPending) {
        state.pendingResponse = null;
        state.pendingFileIndex = state.pendingFiles.indexOf(filename);
    }
    ++state.pendingFileIndex;
    var response = state.pendingResponse || extractFile(command.filename);
    state.pendingResponse = null;
    process.stdout.write(response + "\n", function () {
        prepareNextFile();
    });
}
function isExtractableSourceFile(ast) {
    return ast.redirectInfo == null;
}
function getAstForFile(filename) {
    var _a = parseSingleFile(filename), ast = _a.ast, code = _a.code;
    if (ast != null && isExtractableSourceFile(ast)) {
        ast_extractor.augmentAst(ast, code, null);
    }
    return ast;
}
function parseSingleFile(filename) {
    var code = ts.sys.readFile(filename);
    var compilerHost = {
        fileExists: function () { return true; },
        getCanonicalFileName: function () { return filename; },
        getCurrentDirectory: function () { return ""; },
        getDefaultLibFileName: function () { return "lib.d.ts"; },
        getNewLine: function () { return "\n"; },
        getSourceFile: function () {
            return ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, true);
        },
        readFile: function () { return null; },
        useCaseSensitiveFileNames: function () { return true; },
        writeFile: function () { return null; },
        getDirectories: function () { return []; },
    };
    var compilerOptions = {
        experimentalDecorators: true,
        experimentalAsyncFunctions: true,
        jsx: ts.JsxEmit.Preserve,
        noResolve: true,
    };
    var program = ts.createProgram([filename], compilerOptions, compilerHost);
    var ast = program.getSourceFile(filename);
    return { ast: ast, code: code };
}
var nodeModulesRex = /[/\\]node_modules[/\\]((?:@[\w.-]+[/\\])?\w[\w.-]*)[/\\](.*)/;
function loadTsConfig(command) {
    var tsConfig = ts.readConfigFile(command.tsConfig, ts.sys.readFile);
    var basePath = pathlib.dirname(command.tsConfig);
    var packageEntryPoints = new Map(command.packageEntryPoints);
    var packageJsonFiles = new Map(command.packageJsonFiles);
    var virtualSourceRoot = new virtual_source_root_1.VirtualSourceRoot(command.sourceRoot, command.virtualSourceRoot);
    function redirectNodeModulesPath(path) {
        var nodeModulesMatch = nodeModulesRex.exec(path);
        if (nodeModulesMatch == null)
            return null;
        var packageName = nodeModulesMatch[1];
        var packageJsonFile = packageJsonFiles.get(packageName);
        if (packageJsonFile == null)
            return null;
        var packageDir = pathlib.dirname(packageJsonFile);
        var suffix = nodeModulesMatch[2];
        var finalPath = pathlib.join(packageDir, suffix);
        if (!ts.sys.fileExists(finalPath))
            return null;
        return finalPath;
    }
    var parseConfigHost = {
        useCaseSensitiveFileNames: true,
        readDirectory: function (rootDir, extensions, excludes, includes, depth) {
            var exclusions = excludes == null ? [] : __spreadArray([], excludes, true);
            if (virtualSourceRoot.virtualSourceRoot != null) {
                exclusions.push(virtualSourceRoot.virtualSourceRoot);
            }
            var originalResults = ts.sys.readDirectory(rootDir, extensions, exclusions, includes, depth);
            var virtualDir = virtualSourceRoot.toVirtualPath(rootDir);
            if (virtualDir == null) {
                return originalResults;
            }
            var virtualExclusions = excludes == null ? [] : __spreadArray([], excludes, true);
            virtualExclusions.push('**/node_modules/**/*');
            var virtualResults = ts.sys.readDirectory(virtualDir, extensions, virtualExclusions, includes, depth);
            return __spreadArray(__spreadArray([], originalResults, true), virtualResults, true);
        },
        fileExists: function (path) {
            return ts.sys.fileExists(path)
                || virtualSourceRoot.toVirtualPathIfFileExists(path) != null
                || redirectNodeModulesPath(path) != null;
        },
        readFile: function (path) {
            if (!ts.sys.fileExists(path)) {
                var virtualPath = virtualSourceRoot.toVirtualPathIfFileExists(path);
                if (virtualPath != null)
                    return ts.sys.readFile(virtualPath);
                virtualPath = redirectNodeModulesPath(path);
                if (virtualPath != null)
                    return ts.sys.readFile(virtualPath);
            }
            return ts.sys.readFile(path);
        }
    };
    var config = ts.parseJsonConfigFileContent(tsConfig.config, parseConfigHost, basePath);
    var ownFiles = config.fileNames.map(function (file) { return pathlib.resolve(file); });
    return { config: config, basePath: basePath, packageJsonFiles: packageJsonFiles, packageEntryPoints: packageEntryPoints, virtualSourceRoot: virtualSourceRoot, ownFiles: ownFiles };
}
function handleResetCommand(command) {
    reset();
    console.log(JSON.stringify({
        type: "reset-done",
    }));
}
function handlePrepareFilesCommand(command) {
    state.pendingFiles = command.filenames;
    state.pendingFileIndex = 0;
    state.pendingResponse = null;
    process.stdout.write('{"type":"ok"}\n', function () {
        prepareNextFile();
    });
}
function handleGetMetadataCommand(command) {
    console.log(JSON.stringify({
        type: "metadata",
        syntaxKinds: ts.SyntaxKind,
        nodeFlags: ts.NodeFlags,
    }));
}
function reset() {
    state = new State();
}
function getEnvironmentVariable(name, parse, defaultValue) {
    var value = process.env[name];
    return value != null ? parse(value) : defaultValue;
}
var hasReloadedSinceExceedingThreshold = false;
function checkMemoryUsage() {
    var bytesUsed = process.memoryUsage().heapUsed;
    var megabytesUsed = bytesUsed / 1000000;
    if (!hasReloadedSinceExceedingThreshold && megabytesUsed > reloadMemoryThresholdMb && state.project != null) {
        console.warn('Restarting TypeScript compiler due to memory usage');
        state.project.reload();
        hasReloadedSinceExceedingThreshold = true;
    }
    else if (hasReloadedSinceExceedingThreshold && megabytesUsed < reloadMemoryThresholdMb) {
        hasReloadedSinceExceedingThreshold = false;
    }
}
function runReadLineInterface() {
    reset();
    var rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on("line", function (line) {
        var req = JSON.parse(line);
        switch (req.command) {
            case "parse":
                handleParseCommand(req);
                break;
            case "prepare-files":
                handlePrepareFilesCommand(req);
                break;
            case "reset":
                handleResetCommand(req);
                break;
            case "get-metadata":
                handleGetMetadataCommand(req);
                break;
            case "quit":
                rl.close();
                break;
            default:
                throw new Error("Unknown command " + req.command + ".");
        }
    });
}
if (process.argv.length > 2) {
    var argument = process.argv[2];
    if (argument === "--version") {
        console.log("parser-wrapper with TypeScript " + ts.version);
    }
    else if (pathlib.extname(argument) === ".ts" || pathlib.extname(argument) === ".tsx") {
        handleParseCommand({
            command: "parse",
            filename: argument,
        }, false);
    }
    else {
        console.error("Unrecognized file or flag: " + argument);
    }
    process.exit(0);
}
else {
    runReadLineInterface();
}
