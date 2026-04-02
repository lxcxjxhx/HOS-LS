from setuptools import setup, find_packages

setup(
    name="hos-ls",
    version="1.0.0",
    description="HOS-LS 安全检测工具",
    author="Security Team",
    author_email="security@example.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "pyyaml==6.0.1",
        "markdown==3.5.2",
        "python-docx==0.8.11",
        "jinja2==3.1.3",
        "requests==2.31.0",
        "colorama==0.4.6"
    ],
    entry_points={
        "console_scripts": [
            "hos-ls=src.main:main"
        ]
    }
)
