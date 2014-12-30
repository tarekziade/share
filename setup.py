import sys
from setuptools import setup, find_packages


setup(name='fxakeys',
      version="0.1",
      packages=find_packages(),
      description=("A Key Server"),
      author="Mozilla Foundation & Contributors",
      author_email="services-dev@lists.mozila.org",
      include_package_data=True,
      install_requires=["bottle", "pynacl", "pyfxa", "tinydb"],
      zip_safe=False,
      entry_points="""
      [console_scripts]
      fxakeys = fxakeys.server:main
      """)
