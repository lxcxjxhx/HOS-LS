"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.augmentAst = augmentAst;
var ts = require("./typescript");
function hasOwnProperty(o, p) {
    return o && Object.prototype.hasOwnProperty.call(o, p);
}
var SyntaxKind = [];
for (var p in ts.SyntaxKind) {
    if (!hasOwnProperty(ts.SyntaxKind, p)) {
        continue;
    }
    if (+p === +p) {
        continue;
    }
    if (p.substring(0, 5) === "First" || p.substring(0, 4) === "Last") {
        continue;
    }
    SyntaxKind[ts.SyntaxKind[p]] = p;
}
var skipWhiteSpace = /(?:\s|\/\/.*|\/\*[^]*?\*\/)*/g;
function forEachNode(ast, callback) {
    function visit(node) {
        ts.forEachChild(node, visit);
        callback(node);
    }
    visit(ast);
}
function tryGetTypeOfNode(typeChecker, node) {
    try {
        return typeChecker.getTypeAtLocation(node);
    }
    catch (e) {
        var sourceFile = node.getSourceFile();
        var _a = sourceFile.getLineAndCharacterOfPosition(node.pos), line = _a.line, character = _a.character;
        console.warn("Could not compute type of ".concat(ts.SyntaxKind[node.kind], " at ").concat(sourceFile.fileName, ":").concat(line + 1, ":").concat(character + 1));
        return null;
    }
}
function augmentAst(ast, code, project) {
    ast.$lineStarts = ast.getLineStarts();
    function augmentPos(pos, shouldSkipWhitespace) {
        if (shouldSkipWhitespace) {
            skipWhiteSpace.lastIndex = pos;
            pos += skipWhiteSpace.exec(code)[0].length;
        }
        return pos;
    }
    var reScanEvents = [];
    var reScanEventPos = [];
    var scanner = ts.createScanner(ts.ScriptTarget.ES2015, false, 1, code);
    var reScanSlashToken = scanner.reScanSlashToken.bind(scanner);
    var reScanTemplateToken = scanner.reScanTemplateToken.bind(scanner);
    var reScanGreaterToken = scanner.reScanGreaterToken.bind(scanner);
    if (!ast.parseDiagnostics || ast.parseDiagnostics.length === 0) {
        forEachNode(ast, function (node) {
            if (ts.isRegularExpressionLiteral(node)) {
                reScanEventPos.push(node.getStart(ast, false));
                reScanEvents.push(reScanSlashToken);
            }
            if (ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
                reScanEventPos.push(node.getStart(ast, false));
                reScanEvents.push(reScanTemplateToken);
            }
            if (ts.isBinaryExpression(node)) {
                var operator = node.operatorToken;
                switch (operator.kind) {
                    case ts.SyntaxKind.GreaterThanEqualsToken:
                    case ts.SyntaxKind.GreaterThanGreaterThanEqualsToken:
                    case ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken:
                    case ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken:
                    case ts.SyntaxKind.GreaterThanGreaterThanToken:
                        reScanEventPos.push(operator.getStart(ast, false));
                        reScanEvents.push(reScanGreaterToken);
                        break;
                }
            }
        });
    }
    reScanEventPos.push(Infinity);
    ast.$tokens = [];
    var rescanEventIndex = 0;
    var nextRescanPosition = reScanEventPos[0];
    var tk;
    do {
        tk = scanner.scan();
        if (scanner.getTokenPos() === nextRescanPosition) {
            var callback = reScanEvents[rescanEventIndex];
            callback();
            ++rescanEventIndex;
            nextRescanPosition = reScanEventPos[rescanEventIndex];
        }
        ast.$tokens.push({
            kind: tk,
            tokenPos: augmentPos(scanner.getTokenPos()),
            text: scanner.getTokenText(),
        });
    } while (tk !== ts.SyntaxKind.EndOfFileToken);
    if (ast.parseDiagnostics) {
        ast.parseDiagnostics.forEach(function (d) {
            delete d.file;
            d.$pos = augmentPos(d.start);
        });
    }
    visitAstNode(ast);
    function visitAstNode(node) {
        ts.forEachChild(node, visitAstNode);
        if ("pos" in node) {
            node.$pos = augmentPos(node.pos, true);
        }
        if ("end" in node) {
            node.$end = augmentPos(node.end);
        }
        if (ts.isVariableDeclarationList(node)) {
            var tz = ts;
            if (typeof tz.isLet === "function" && tz.isLet(node) || (node.flags & ts.NodeFlags.Let)) {
                node.$declarationKind = "let";
            }
            else if (typeof tz.isConst === "function" && tz.isConst(node) || (node.flags & ts.NodeFlags.Const)) {
                node.$declarationKind = "const";
            }
            else {
                node.$declarationKind = "var";
            }
        }
    }
}
