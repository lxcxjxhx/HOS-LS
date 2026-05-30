"""FrameworkRouteRecognizer 单元测试

验证各框架路由识别、URL 模式提取和 HTTP 方法识别。
"""
import pytest

from src.analysis.framework_patterns import (
    FrameworkRouteRecognizer, RouteInfo, integrate_routes_to_graph,
    match_framework_patterns, check_safe_pattern, check_unsafe_pattern,
)


class TestDjangoRoutes:

    def test_recognize_path(self):
        recognizer = FrameworkRouteRecognizer()
        code = "path('users/', views.UserView)"
        routes = recognizer.recognize("urls.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "users/"
        assert routes[0].framework == "django"
        assert routes[0].handler_name == "views.UserView"

    def test_recognize_re_path(self):
        recognizer = FrameworkRouteRecognizer()
        code = "re_path(r'^api/v1/', views.api_handler)"
        routes = recognizer.recognize("urls.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "^api/v1/"
        assert routes[0].framework == "django"

    def test_recognize_url(self):
        recognizer = FrameworkRouteRecognizer()
        code = "url('admin/', admin.site.urls)"
        routes = recognizer.recognize("urls.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "admin/"
        assert routes[0].framework == "django"

    def test_recognize_multiple_django_routes(self):
        recognizer = FrameworkRouteRecognizer()
        code = (
            "path('users/', views.list_users)\n"
            "path('posts/', views.list_posts)\n"
        )
        routes = recognizer.recognize("urls.py", code, "python")
        assert len(routes) == 2
        patterns = [r.url_pattern for r in routes]
        assert "users/" in patterns
        assert "posts/" in patterns


class TestFlaskRoutes:

    def test_recognize_route_get(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.route('/users')\ndef get_users(): pass"
        routes = recognizer.recognize("app.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/users"
        assert routes[0].framework == "flask"
        assert "GET" in routes[0].http_methods

    def test_recognize_route_with_methods(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.route('/users', methods=['GET', 'POST'])\ndef handle_users(): pass"
        routes = recognizer.recognize("app.py", code, "python")
        assert len(routes) == 1
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods

    def test_recognize_route_extracts_handler(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.route('/items')\ndef list_items(): pass"
        routes = recognizer.recognize("app.py", code, "python")
        assert len(routes) == 1
        assert routes[0].handler_name == "list_items"


class TestFastAPIRoutes:

    def test_recognize_get(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.get('/items')\ndef get_items(): pass"
        routes = recognizer.recognize("main.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/items"
        assert routes[0].framework == "fastapi"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_post(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.post('/items')\ndef create_item(): pass"
        routes = recognizer.recognize("main.py", code, "python")
        assert len(routes) == 1
        assert routes[0].http_methods == ["POST"]

    def test_recognize_put(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@router.put('/items/{id}')\ndef update_item(): pass"
        routes = recognizer.recognize("main.py", code, "python")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/items/{id}"
        assert routes[0].http_methods == ["PUT"]

    def test_recognize_delete(self):
        recognizer = FrameworkRouteRecognizer()
        code = "@app.delete('/items/{id}')\ndef delete_item(): pass"
        routes = recognizer.recognize("main.py", code, "python")
        assert len(routes) == 1
        assert routes[0].http_methods == ["DELETE"]


class TestExpressRoutes:

    def test_recognize_app_get(self):
        recognizer = FrameworkRouteRecognizer()
        code = "app.get('/api/users', handler)"
        routes = recognizer.recognize("server.js", code, "javascript")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/api/users"
        assert routes[0].framework == "express"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_app_post(self):
        recognizer = FrameworkRouteRecognizer()
        code = "app.post('/api/users', createUser)"
        routes = recognizer.recognize("server.js", code, "javascript")
        assert len(routes) == 1
        assert routes[0].http_methods == ["POST"]
        assert routes[0].handler_name == "createUser"

    def test_recognize_router_get(self):
        recognizer = FrameworkRouteRecognizer()
        code = "router.get('/posts', listPosts)"
        routes = recognizer.recognize("routes.js", code, "javascript")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/posts"
        assert routes[0].framework == "express"

    def test_recognize_typescript(self):
        recognizer = FrameworkRouteRecognizer()
        code = "app.delete('/api/items/:id', deleteItem)"
        routes = recognizer.recognize("server.ts", code, "typescript")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/api/items/:id"
        assert routes[0].http_methods == ["DELETE"]


class TestSpringRoutes:

    def test_recognize_get_mapping(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@GetMapping("/users")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/users"
        assert routes[0].framework == "spring"
        assert routes[0].http_methods == ["GET"]

    def test_recognize_post_mapping(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@PostMapping("/users")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].http_methods == ["POST"]

    def test_recognize_put_mapping(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@PutMapping("/users/{id}")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].url_pattern == "/users/{id}"
        assert routes[0].http_methods == ["PUT"]

    def test_recognize_delete_mapping(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@DeleteMapping("/users/{id}")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].http_methods == ["DELETE"]

    def test_recognize_patch_mapping(self):
        recognizer = FrameworkRouteRecognizer()
        code = '@PatchMapping("/users/{id}")'
        routes = recognizer.recognize("UserController.java", code, "java")
        assert len(routes) == 1
        assert routes[0].http_methods == ["PATCH"]


class TestUnsupportedFrameworks:

    def test_unsupported_language_returns_empty(self):
        recognizer = FrameworkRouteRecognizer()
        routes = recognizer.recognize("foo.go", "func main() {}", "go")
        assert routes == []

    def test_unknown_language_returns_empty(self):
        recognizer = FrameworkRouteRecognizer()
        routes = recognizer.recognize("foo.rs", "fn main() {}", "rust")
        assert routes == []

    def test_no_routes_in_code(self):
        recognizer = FrameworkRouteRecognizer()
        routes = recognizer.recognize("foo.py", "x = 1", "python")
        assert routes == []


class TestRouteInfoDataclass:

    def test_route_info_fields(self):
        route = RouteInfo(
            url_pattern="/api",
            handler_name="handler",
            handler_file="/app.py",
            handler_line=1,
            http_methods=["GET"],
            framework="flask",
        )
        assert route.url_pattern == "/api"
        assert route.handler_name == "handler"
        assert route.handler_file == "/app.py"
        assert route.handler_line == 1
        assert route.http_methods == ["GET"]
        assert route.framework == "flask"


class TestPatternMatchers:

    def test_match_safe_patterns(self):
        code = "Wrappers.query().eq('id', 1)"
        result = match_framework_patterns(code)
        assert len(result['safe']) > 0

    def test_match_unsafe_patterns(self):
        code = "${user_input}"
        result = match_framework_patterns(code)
        assert len(result['unsafe']) > 0

    def test_check_safe_pattern_true(self):
        assert check_safe_pattern("Wrappers.lambdaQuery()") is True

    def test_check_safe_pattern_false(self):
        assert check_safe_pattern("no safe pattern here") is False

    def test_check_unsafe_pattern_true(self):
        assert check_unsafe_pattern("${}") is True

    def test_check_unsafe_pattern_false(self):
        assert check_unsafe_pattern("#{safe}") is False


class TestIntegrateRoutesToGraph:

    def test_integrate_no_routes(self):
        mock_engine = MagicMock()
        mock_engine._db = None
        from unittest.mock import MagicMock
        routes = integrate_routes_to_graph(mock_engine, "foo.py", "x = 1", "python")
        assert routes == []
