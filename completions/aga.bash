# bash completion for the `aga` command (Attack Graph Analysis).
# Install to /etc/bash_completion.d/aga or
# /usr/share/bash-completion/completions/aga .

_aga_complete() {
    local cur prev words cword
    _init_completion || return

    # Flags that take a value requiring file/path completion.
    case "$prev" in
        --dir|--graphs-dir|--discover|--wifi-from-file|--nmap|--export)
            _filedir
            return
            ;;
        --construct)
            COMPREPLY=($(compgen -W "3-tier-webapp dmz-internal flat-lan" -- "$cur"))
            return
            ;;
        --scan-wifi|--nmap-live)
            # Suggest network interfaces (best-effort).
            COMPREPLY=($(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur"))
            return
            ;;
        --explain-cvss)
            # Common CVSS Exploitability vectors as a starting point.
            COMPREPLY=($(compgen -W \
                "AV:N/AC:L/PR:N/UI:N AV:N/AC:L/PR:N/UI:R AV:A/AC:L/PR:L/UI:N \
                 AV:L/AC:H/PR:H/UI:N AV:P/AC:H/PR:H/UI:R" -- "$cur"))
            return
            ;;
    esac

    # A flag that takes no value, or the first word: offer all options + files.
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "
            -V --version -h --help
            --dir --graphs-dir --list --no-plot
            --explain-cvss --list-templates --construct --discover
            --wifi-from-file --scan-wifi --i-am-authorized --wifi-rescan
            --nmap --nmap-live --export
        " -- "$cur"))
        return
    fi

    # Otherwise complete on JSON graph configs.
    _filedir json
} &&
complete -F _aga_complete aga
