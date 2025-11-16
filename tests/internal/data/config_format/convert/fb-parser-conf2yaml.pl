#!/usr/bin/env perl
use strict;
use warnings;
use utf8;

# Convert Fluent Bit parser .conf files to YAML format
#
# N.B.:
#
# - Currently only supports parser*.conf files, not other .conf files.
#
# - Uses hardcoded indentations to match existing examples.
#
# - Supports up to one [PARSER] followed by up to one [MULTILINE_PARSER],
#   which covers every existing example, but might not actually be
#   a hard requirement of Fluent Bit's .conf format.

# Simple key:value keywords we can rewrite when we see them commented out
my @KNOWN_KEYWORDS = qw(
	Format Name Regex Time_Keep Time_Key Time_Format Types
);

# Build a case-insensitive regex from those keywords
my $keyword_pattern = join('|', map { quotemeta($_) } @KNOWN_KEYWORDS);
my $keyword_regex = qr/^#\s*($keyword_pattern)\s+(.+)$/i;

sub parse_rule_value
{
  my ($value) = @_;
  
  # Parse rule format: "state" "regex" "next_state"
  if ($value =~ /^\s*"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"/)
  {
    return
    {
      state => $1,
      regex => $2,
      next_state => $3
    };
  }
  
  return undef;  # Parsing failed
}

sub transform_commented_keyword
{
  my ($stripped) = @_;
  
  return $stripped unless $stripped =~ $keyword_regex;
  
  my ($key, $value) = ($1, $2);
  my $yaml_key = lc($key);
  
  # Transform to YAML key:value format
  my $yaml_value = &format_yaml_value($value);
  return "#$yaml_key: $yaml_value";
}

sub parse_conf_file
{
  my ($content) = @_;
  my @parsers;
  my @multiline_parsers;
  my $rhcurrent_parser;
  # 'PARSER' or 'MULTILINE_PARSER'
  my $current_type;
  my @pending_comments;
  my $parser_has_fields = 0;
  # There may be global comments before stanzas start
  my @file_comments;
  my $seen_section = 0;
  # Track if there's a blank before a comment block, so we know
  # whether to merge into the stanza above or not.
  my $blank_before_comments = 0;
  # There may be global comments at end of file
  my @trailing_comments;
  
  for my $line (split /\n/, $content)
  {
    my $stripped = $line;
    $stripped =~ s/^\s+|\s+$//g;  # trim
    
    # Skip empty lines
    if (!$stripped)
    {
      # If we have pending comments, this blank line might separate them from next section
      if (@pending_comments)
      {
        push @pending_comments, '';
      }
      else
      {
        # Mark that we've seen a blank line (potentially before comments)
        $blank_before_comments = 1;
      }
      next;
    }
    
    # Collect comments
    if ($stripped =~ /^#/)
    {
      push @pending_comments, &transform_commented_keyword($stripped);
      next;
    }
    
    # Check for section headers
    if ($stripped =~ /^\[(\w+)\]$/)
    {
      # Normalize to uppercase
      my $section = uc($1);
      
      # Save comments before first section as file-level comments
      if (!$seen_section && @pending_comments)
      {
        @file_comments = @pending_comments;
        @pending_comments = ();
        $blank_before_comments = 0;
      }
      $seen_section = 1;
      
      # If we have pending comments with a blank line before them,
      # they belong to the new section (leading comments)
      # Otherwise they belong to the previous section (trailing comments)
      my $rapending_for_save;
      if (@pending_comments && !$blank_before_comments)
      {
        # Comments belong to previous parser (no blank line before them)
        if ($rhcurrent_parser)
        {
          $rhcurrent_parser->{_inline_comments} //= [];
          push @{$rhcurrent_parser->{_inline_comments}}, @pending_comments;
        }
        @pending_comments = ();
        $rapending_for_save = \@pending_comments;  # Empty array ref
      }
      elsif (@pending_comments && $blank_before_comments)
      {
        # Comments belong to next parser - don't pass to save_current_parser
        $rapending_for_save = [];  # Empty array ref
      }
      else
      {
        # No pending comments
        $rapending_for_save = \@pending_comments;
      }
      
      # Save previous parser
      &save_current_parser($rhcurrent_parser, $current_type, $rapending_for_save, 
        \@parsers, \@multiline_parsers);
      
      # Reset blank line flag after processing
      $blank_before_comments = 0;

      if ($section eq 'PARSER' || $section eq 'MULTILINE_PARSER')
      {
        $current_type = $section;
        $rhcurrent_parser =
        {
          _comments => [],
          _fields => []
        };
        $parser_has_fields = 0;
        
        # Attach any pending comments to this parser (leading comments with blank before)
        if (@pending_comments)
        {
          $rhcurrent_parser->{_comments} = [@pending_comments];
          @pending_comments = ();
        }
      }
      else
      {
        # Unsupported section type
        warn "Warning: Unsupported section type [$section] - can only handle [PARSER] and [MULTILINE_PARSER]\n";
        $rhcurrent_parser = undef;
        $current_type = undef;
      }
      next;
    }
    
    # Parse key-value pairs
    if ($rhcurrent_parser && $stripped =~ /^(\S+)\s+(.+)$/)
    {
      my ($key, $value) = ($1, $2);
      
      # Reset blank line flag when we see actual content
      $blank_before_comments = 0;
      
      # If we have pending comments, add them before this field
      if (@pending_comments)
      {
        if (!$parser_has_fields)
        {
          # Comments before any fields are leading comments
          push @{$rhcurrent_parser->{_comments}}, @pending_comments;
        }
        else
        {
          # Comments after first field - store inline with fields
          for my $comment (@pending_comments)
          {
            push @{$rhcurrent_parser->{_fields}}, ['_comment_', $comment];
          }
        }
        @pending_comments = ();
      }
      
      # Convert key to lowercase with underscores
      my $yaml_key = lc($key);
      
      # Special handling for multiline parser 'rule' fields
      if ($current_type eq 'MULTILINE_PARSER' && $yaml_key eq 'rule')
      {
        my $rhrule = &parse_rule_value($value);
        if ($rhrule)
        {
          # Store as a structured rule
          push @{$rhcurrent_parser->{_fields}}, ['_rule_', $rhrule];
        }
        else
        {
          # Fallback: store as-is if parsing fails
          warn "Warning: Could not parse rule format: $value\n";
          push @{$rhcurrent_parser->{_fields}}, [$yaml_key, $value];
        }
      }
      else
      {
        # Store field in order
        push @{$rhcurrent_parser->{_fields}}, [$yaml_key, $value];
      }
      $parser_has_fields = 1;
    }
  }
  
  # Handle any remaining comments at end of file
  # If there's a blank line before them, they're trailing file comments
  if (@pending_comments && $blank_before_comments)
  {
    @trailing_comments = @pending_comments;
    @pending_comments = ();
  }
  
  # Don't forget the last parser and any trailing comments
  &save_current_parser($rhcurrent_parser, $current_type, \@pending_comments,
    \@parsers, \@multiline_parsers);
  
  return (\@file_comments, \@parsers, \@multiline_parsers, \@trailing_comments);
}

sub format_yaml_value
{
  my ($value) = @_;
  
  # Check if value needs quoting
  # Quote values that start with special chars or contain : or # or %
  if ($value && 
    ($value =~ /^[!&*{\[|>'"]/ || 
     $value =~ /[:#]/ || 
     $value =~ /^%/))
  {
    # Use single quotes and escape any single quotes in the value
    $value =~ s/'/''/g;
    return "'$value'";
  }
  
  return $value;
}

sub output_comments
{
  my ($racomments, $ralines, $indent) = @_;
  $indent //= '';
  
  for my $comment (@$racomments)
  {
    if ($comment)
    {
      push @$ralines, "$indent$comment";
    }
    else
    {
      push @$ralines, "$indent#";
    }
  }
}

sub save_current_parser
{
  my ($rhcurrent_parser, $current_type, $rapending_comments, $raparsers, $ramultiline_parsers) = @_;
  
  return unless $rhcurrent_parser;
  
  # Add any remaining inline comments
  if (@$rapending_comments)
  {
    $rhcurrent_parser->{_inline_comments} //= [];
    push @{$rhcurrent_parser->{_inline_comments}}, @$rapending_comments;
    @$rapending_comments = ();
  }
  
  # Save to appropriate list
  if ($current_type eq 'PARSER')
  {
    push @$raparsers, $rhcurrent_parser;
  }
  elsif ($current_type eq 'MULTILINE_PARSER')
  {
    push @$ramultiline_parsers, $rhcurrent_parser;
  }
}

sub output_section
{
  my ($section_name, $raitems, $ralines) = @_;
  
  return unless @$raitems;
  
  # Insert a blank line between sections
  push @$ralines, '' if @$ralines;

  push @$ralines, "$section_name:";
  
  for my $idx (0 .. $#$raitems)
  {
    # Insert a blank line between items
    push @$ralines, '' if $idx > 0;

    &output_parser_item($raitems->[$idx], $ralines);
  }
}

sub output_parser_item
{
  my ($rhparser, $ralines) = @_;
  
  # Extract and remove comments from the parser hash
  my @comments = @{delete $rhparser->{_comments} // []};
  my @inline_comments = @{delete $rhparser->{_inline_comments} // []};
  my @fields = @{delete $rhparser->{_fields} // []};
  
  # Collect rules for multiline parsers
  my @rules;
  my @non_rule_fields;
  for my $rafield (@fields)
  {
    my ($key, $value) = @$rafield;
    if ($key eq '_rule_')
    {
      push @rules, $value;
    }
    else
    {
      push @non_rule_fields, $rafield;
    }
  }
  
  # Start the parser list item
  my $first_field = 1;
  for my $rafield (@non_rule_fields)
  {
    my ($key, $value) = @$rafield;
    
    # Handle inline comments
    if ($key eq '_comment_')
    {
      if ($value)
      {
        push @$ralines, "    $value";
      }
      else
      {
        push @$ralines, '    #';
      }
      next;
    }
    
    if ($first_field)
    {
      # First field gets the list marker
      push @$ralines, "  - $key: " . &format_yaml_value($value);
      $first_field = 0;
      
      # Add leading comments after the name field
      &output_comments(\@comments, $ralines, '    ');
    }
    else
    {
      # Subsequent fields are indented
      push @$ralines, "    $key: " . &format_yaml_value($value);
    }
  }
  
  # Output rules array if we have any
  if (@rules)
  {
    push @$ralines, "    rules:";
    for my $idx (0 .. $#rules)
    {
      my $rhrule = $rules[$idx];
      
      # Add blank line before rules after the first one
      push @$ralines, '' if $idx > 0;
      
      push @$ralines, "      - state: $rhrule->{state}";
      push @$ralines, "        regex: " . &format_yaml_value($rhrule->{regex});
      push @$ralines, "        next_state: $rhrule->{next_state}";
    }
  }
  
  # Add trailing inline comments
  &output_comments(\@inline_comments, $ralines, '    ');
}

sub convert_to_yaml
{
  my ($rafile_comments, $raparsers, $ramultiline_parsers, $ratrailing_comments) = @_;
  my @lines;
  
  # Add file-level comments at the top
  &output_comments($rafile_comments, \@lines);
  
  # Output sections
  &output_section('parsers', $raparsers, \@lines);
  &output_section('multiline_parsers', $ramultiline_parsers, \@lines);
  
  # Add trailing comments at the end
  if (@$ratrailing_comments)
  {
    push @lines, '';  # Blank line before trailing comments
    &output_comments($ratrailing_comments, \@lines);
  }
  
  return join("\n", @lines) . "\n";
}

# Main
if (@ARGV < 1)
{
  print "Usage: fb-parser-conf2yaml.pl <input1.conf> [input2.conf ...]\n";
  print "Converts each input file to YAML, creating output files with .yaml suffix\n";
  exit 1;
}

for my $input_file (@ARGV)
{
  # Check if input file exists
  unless (-f $input_file)
  {
    warn "Warning: Input file '$input_file' not found, skipping\n";
    next;
  }
  
  # Generate output filename
  my $output_file = $input_file;
  $output_file =~ s/\.(conf|config|cnf|cfg)$//i;  # Strip common config extensions
  $output_file .= '.yaml';
  
  # Check if output file already exists and has nonzero size
  if (-s $output_file)
  {
    warn "Warning: Output file '$output_file' already exists and is non-empty, skipping\n";
    next;
  }
  
  # Read the input file
  open my $fh, '<:utf8', $input_file or do
  {
    warn "Warning: Cannot open '$input_file': $!, skipping\n";
    next;
  };
  my $content = do { local $/; <$fh> };
  close $fh;
  
  # Parse and convert
  my ($rafile_comments, $raparsers, $ramultiline_parsers, $ratrailing_comments) = &parse_conf_file($content);
  my $yaml_output = &convert_to_yaml($rafile_comments, $raparsers, $ramultiline_parsers, $ratrailing_comments);
  
  # Write output
  open my $out_fh, '>:utf8', $output_file or do
  {
    warn "Warning: Cannot write '$output_file': $!, skipping\n";
    next;
  };
  print $out_fh $yaml_output;
  close $out_fh;
  
  print "Converted $input_file -> $output_file\n";
}
