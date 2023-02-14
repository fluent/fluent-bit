#!/usr/bin/ruby

# Enable all rules by default
all

# Extend line length, since each sentence should be on a separate line.
rule 'MD013', :line_length => 99999, :ignore_code_blocks => true

# Allow in-line HTML
exclude_rule 'MD033'

# Nested lists should be indented with two spaces.
rule 'MD007', :indent => 2

# Bash defaulting confuses this and now way to ignore code blocks
exclude_rule 'MD029'
