import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="esilsolve", 
    version="0.0.1",
    author="Austin Emmitt",
    author_email="aemmitt@nowsecure.com",
    description="A symbolic execution tool using r2 and ESIL",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/nowsecure/research/esilsolve",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'r2pipe',
        'z3-solver'
    ]
)