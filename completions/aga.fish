# fish completion for the `aga` command (Attack Graph Analysis).
# Install to /usr/share/fish/vendor_completions.d/aga.fish or
# ~/.config/fish/completions/aga.fish .

# Options that take no argument.
complete -c aga -f -a "(__fish_use_subcommand)" -d "Attack Graph Analysis"

complete -c aga -s V -l version -d "Print version and exit"
complete -c aga -s h -l help    -d "Show help and exit"
complete -c aga -l list            -d "List available graph presets and exit"
complete -c aga -l list-templates  -d "List built-in construction templates and exit"
complete -c aga -l no-plot         -d "Skip generating the graph visualisation"
complete -c aga -l i-am-authorized -d "Assert authorization to scan"
complete -c aga -l wifi-rescan     -d "Trigger a fresh nmcli rescan first"

# Options that take a file/directory argument.
complete -c aga -l dir           -r -f -a "(__fish_complete_directories)" -d "Analyse every *.json config in a directory and compare"
complete -c aga -l graphs-dir    -r -f -a "(__fish_complete_directories)" -d "Directory of preset graph configs"
complete -c aga -l discover      -r -F                            -d "Construct from a discovery JSON file"
complete -c aga -l wifi-from-file -r -F                           -d "Construct a WiFi graph from a captured nmcli scan"
complete -c aga -l nmap          -r -f -a "(__fish_complete_suffix .xml)" -d "Construct a graph from an nmap XML file"
complete -c aga -l export        -r -F                            -d "Also export the analysed graph"
complete -c aga -l explain-cvss  -r                               -d "Explain how a CVSS vector becomes a weight"
complete -c aga -l nmap-live     -r                               -d "Run nmap LIVE against a target"

# Templates and interfaces.
complete -c aga -l construct -r -f -a "3-tier-webapp dmz-internal flat-lan" -d "Construct a graph from a template"
complete -c aga -l scan-wifi -r -f -a "(__fish_print_interfaces)"          -d "Run a LIVE passive WiFi scan"

# Positional argument: a JSON graph config.
complete -c aga -r -f -a "(__fish_complete_suffix .json)"
