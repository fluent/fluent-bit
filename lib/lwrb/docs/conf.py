# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))
from sphinx.builders.html import StandaloneHTMLBuilder
import subprocess, os

# Run doxygen first
# read_the_docs_build = os.environ.get('READTHEDOCS', None) == 'True'
# if read_the_docs_build:
subprocess.call('doxygen doxyfile.doxy', shell=True)
# -- Project information -----------------------------------------------------

project = 'LwRB'
copyright = '2022, Tilen MAJERLE'
author = 'Tilen MAJERLE'

# Try to get branch at which this is running
# and try to determine which version to display in sphinx
# Version is using git tag if on master/main or "latest-develop" if on develop branch
version = ''
git_branch = ''

def cmd_exec_print(t):
    print("cmd > ", t, "\n", os.popen(t).read().strip(), "\n")

# Print demo data here
cmd_exec_print('git branch')
cmd_exec_print('git describe')
cmd_exec_print('git describe --tags')
cmd_exec_print('git describe --tags --abbrev=0')
cmd_exec_print('git describe --tags --abbrev=1')

# Get current branch
res = os.popen('git branch').read().strip()
for line in res.split("\n"):
    if line[0] == '*':
        git_branch = line[1:].strip()

# Decision for display version
git_branch = git_branch.replace('(HEAD detached at ', '').replace(')', '')
if git_branch.find('master') >= 0 or git_branch.find('main') >= 0:
    #version = os.popen('git describe --tags --abbrev=0').read().strip()
    version = 'latest-stable'
elif git_branch.find('develop-') >= 0 or git_branch.find('develop/') >= 0:
    version = 'branch-' + git_branch
elif git_branch == 'develop' or git_branch == 'origin/develop':
    version = 'latest-develop'
else:
    version = os.popen('git describe --tags --abbrev=0').read().strip()

# For debugging purpose only
print("GIT BRANCH: " + git_branch)
print("PROJ VERSION: " + version)

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.autosectionlabel',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.mathjax',
    'sphinx.ext.ifconfig',
    'sphinx.ext.viewcode',
    'sphinx_sitemap',

    'breathe',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

highlight_language = 'c'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'canonical_url': '',
    'analytics_id': '',  #  Provided by Google in your dashboard
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,

    'logo_only': False,

    # Toc options
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False
}
html_logo = 'static/images/logo.svg'
github_url = 'https://github.com/MaJerle/lwrb'
html_baseurl = 'https://docs.majerle.eu/projects/lwrb/'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['static']
html_css_files = [
    'css/common.css',
    'css/custom.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css',
]
html_js_files = [
    ''
]

# Master index file
master_doc = 'index'

# --- Breathe configuration -----------------------------------------------------
breathe_projects = {
	"lwrb": "_build/xml/"
}
breathe_default_project = "lwrb"
breathe_default_members = ('members', 'undoc-members')
breathe_show_enumvalue_initializer = True