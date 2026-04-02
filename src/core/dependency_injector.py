from .module_registry import module_registry

class DependencyInjector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DependencyInjector, cls).__new__(cls)
        return cls._instance

    def inject(self, module_name, **kwargs):
        if not module_registry.has_module(module_name):
            raise ValueError(f"Module '{module_name}' not registered")

        module = module_registry.get_module(module_name)
        dependencies = module_registry.get_dependencies(module_name)

        injected_dependencies = {}
        for dep_name in dependencies:
            if dep_name not in kwargs:
                injected_dependencies[dep_name] = self.inject(dep_name)
            else:
                injected_dependencies[dep_name] = kwargs[dep_name]

        if isinstance(module, type):
            return module(**injected_dependencies)
        elif callable(module):
            return module(**injected_dependencies)
        else:
            return module

    def inject_instance(self, instance, **dependencies):
        for name, dep in dependencies.items():
            if hasattr(instance, name):
                setattr(instance, name, dep)
        return instance

    def get_injected_module(self, module_name, **kwargs):
        return self.inject(module_name, **kwargs)

dependency_injector = DependencyInjector()
