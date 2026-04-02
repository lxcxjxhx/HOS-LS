import importlib
import inspect
from .module_registry import module_registry

class ModulePreloader:
    _instance = None
    _required_modules = set()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModulePreloader, cls).__new__(cls)
        return cls._instance

    def register_required_module(self, module_path, class_name=None):
        if class_name:
            self._required_modules.add((module_path, class_name))
        else:
            self._required_modules.add((module_path, None))

    def preload_all(self):
        missing_modules = []
        for module_path, class_name in self._required_modules:
            try:
                module = importlib.import_module(module_path)
                if class_name:
                    if not hasattr(module, class_name):
                        missing_modules.append(f"Class '{class_name}' in module '{module_path}'")
                module_registry.register_module(module_path, module)
            except ImportError:
                missing_modules.append(f"Module '{module_path}'")
            except Exception as e:
                missing_modules.append(f"Module '{module_path}': {str(e)}")

        if missing_modules:
            raise ImportError(f"Missing required modules/classes: {', '.join(missing_modules)}")

    def preload_module(self, module_path, class_name=None):
        try:
            module = importlib.import_module(module_path)
            if class_name:
                if not hasattr(module, class_name):
                    raise ImportError(f"Class '{class_name}' not found in module '{module_path}'")
                module_registry.register_module(f"{module_path}.{class_name}", getattr(module, class_name))
            else:
                module_registry.register_module(module_path, module)
            return True
        except Exception as e:
            print(f"Error preloading {module_path}: {str(e)}")
            return False

    def validate_module(self, module_name):
        if not module_registry.has_module(module_name):
            return False
        module = module_registry.get_module(module_name)
        return module is not None

    def clear_required_modules(self):
        self._required_modules.clear()

module_preloader = ModulePreloader()
