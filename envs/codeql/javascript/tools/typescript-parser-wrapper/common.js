"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Project = void 0;
var ts = require("./typescript");
var Project = (function () {
    function Project(tsConfig, config, packageEntryPoints) {
        this.tsConfig = tsConfig;
        this.config = config;
        this.packageEntryPoints = packageEntryPoints;
        this.program = null;
        var host = ts.createCompilerHost(config.options, true);
        host.trace = undefined;
        this.host = host;
    }
    Project.prototype.unload = function () {
        this.program = null;
    };
    Project.prototype.load = function () {
        var _a = this, config = _a.config, host = _a.host;
        this.program = ts.createProgram(config.fileNames, config.options, host);
    };
    Project.prototype.reload = function () {
        this.unload();
        this.load();
    };
    return Project;
}());
exports.Project = Project;
