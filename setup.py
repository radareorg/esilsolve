import setuptools
import subprocess
import shutil

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="esilsolve", 
    version="0.0.2",
    author="Austin Emmitt",
    author_email="aemmitt@nowsecure.com",
    description="A symbolic execution tool using r2 and ESIL",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/radareorg/esilsolve",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'r2pipe',
        'z3-solver',
        'colorama',
        # 'frida' # optional for better r2frida support
    ]
)

#plugin_dir = subprocess.check_output(["r2", "-H", "R2_USER_PLUGINS"]).decode()
#shutil.copy(shutil.os.path.join("tools", "esplugin.py"), plugin_dir.strip())
