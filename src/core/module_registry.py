class ModuleRegistry:
    _instance = None
    _modules = {}
    _dependencies = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModuleRegistry, cls).__new__(cls)
        return cls._instance

    def register_module(self, name, module, dependencies=None):
        if dependencies is None:
            dependencies = []
        self._modules[name] = module
        self._dependencies[name] = dependencies

    def get_module(self, name):
        if name not in self._modules:
            raise ValueError(f"Module '{name}' not registered")
        return self._modules[name]

    def get_dependencies(self, name):
        return self._dependencies.get(name, [])

    def has_module(self, name):
        return name in self._modules

    def list_modules(self):
        return list(self._modules.keys())

    def clear(self):
        self._modules.clear()
        self._dependencies.clear()

module_registry = ModuleRegistry()
