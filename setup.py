from setuptools import setup, find_packages

setup(
    name="trailstax",
    version="0.1.0",
    description="Tamper-proof, append-only audit trails and code commit registry for AI agents. First implementation of the RealAgentID protocol.",
    author="CrossroadCode",
    url="https://github.com/TrailStax/trailstax",
    packages=find_packages(),
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
    ],
)
