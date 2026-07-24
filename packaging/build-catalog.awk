BEGIN {
    nrepos = split(repo_paths, repos, " ")
}

function is_version(v) {
    return v ~ /^[0-9]+\.[0-9]+(\.[0-9]+)*$/
}

function schema_version(name) {
    if (name !~ /^fluent-bit-schema-[0-9]+\.[0-9]+(\.[0-9]+)*\.json$/) {
        return ""
    }
    sub(/^fluent-bit-schema-/, "", name)
    sub(/\.json$/, "", name)
    return name
}

function extract_version(name,    rest, i, c, following) {
    if (substr(name, 1, 11) == "fluent-bit-") {
        rest = substr(name, 12)
    } else if (substr(name, 1, 11) == "fluent-bit_") {
        rest = substr(name, 12)
    } else {
        return ""
    }

    for (i = 1; i <= length(rest); i++) {
        c = substr(rest, i, 1)
        if (c == ".") {
            if (i < length(rest)) {
                following = substr(rest, i + 1, 1)
                if (following !~ /[0-9]/) {
                    if (i == 1) {
                        return ""
                    }
                    return substr(rest, 1, i - 1)
                }
            }
            continue
        }
        if (c < "0" || c > "9") {
            if (i == 1) {
                return ""
            }
            return substr(rest, 1, i - 1)
        }
    }

    return rest
}

function version_includes_linux(v) {
    return v ~ /^[45]\./
}

function repo_prefix(path,    i, p) {
    for (i = 1; i <= nrepos; i++) {
        p = repos[i]
        if (p == "") {
            continue
        }
        if (index(path, p "/") == 1) {
            return p
        }
    }
    return ""
}

function is_deb_repo(repo) {
    return index(repo, "debian/") == 1 || index(repo, "ubuntu/") == 1 \
        || index(repo, "raspbian/") == 1
}

function is_canonical_linux_path(path, repo) {
    if (repo == "") {
        return 0
    }
    if (is_deb_repo(repo)) {
        return index(path, "/pool/") > 0
    }
    return 1
}

function is_downloadable_linux(name) {
    return name ~ /^fluent-bit-[0-9]+(\.[0-9]+)+-[0-9]+\.(x86_64|aarch64|arm64)\.rpm$/ \
        || name ~ /^fluent-bit_[0-9]+(\.[0-9]+)+_(amd64|arm64|aarch64)\.deb$/
}

function make_linux_label(path, name, repo,    arch, format) {
    format = ""
    arch = ""
    if (name ~ /\.rpm$/) {
        format = "rpm"
        if (match(name, /\.(x86_64|aarch64|arm64)\.rpm$/)) {
            arch = substr(name, RSTART + 1, RLENGTH - 5)
        }
    } else if (name ~ /\.deb$/) {
        format = "deb"
        if (match(name, /_(amd64|arm64|aarch64)\.deb$/)) {
            arch = substr(name, RSTART + 1, RLENGTH - 5)
        }
    }
    return repo " " arch " " format
}

function json_str(s) {
    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    return "\"" s "\""
}

function json_url(path) {
    if (path == "") {
        return "null"
    }
    return json_str(base_url "/" path)
}

function note_linux(v, path, name, repo,    key, label, idx) {
    if (!version_includes_linux(v)) {
        return
    }
    key = v SUBSEP path
    if (linux_seen[key]) {
        return
    }
    linux_seen[key] = 1
    label = make_linux_label(path, name, repo)
    linux_count[v]++
    idx = linux_count[v]
    linux_path[v, idx] = path
    linux_repo[v, idx] = repo
    linux_name[v, idx] = name
    linux_lbl[v, idx] = label
    linux_repo_set[v SUBSEP repo] = 1
}

function windows_key(name, v) {
    if (name == "fluent-bit-" v "-win32.exe") {
        return "win32_exe"
    }
    if (name == "fluent-bit-" v "-win32.zip") {
        return "win32_zip"
    }
    if (name == "fluent-bit-" v "-win64.exe") {
        return "win64_exe"
    }
    if (name == "fluent-bit-" v "-win64.zip") {
        return "win64_zip"
    }
    if (name == "fluent-bit-" v "-winarm64.exe") {
        return "winarm64_exe"
    }
    if (name == "fluent-bit-" v "-winarm64.zip") {
        return "winarm64_zip"
    }
    return ""
}

function emit_version(v,    out, i, repo_key, repo, repos_out, repos_n) {
    out = "{"
    out = out "\"version\":" json_str(v) ","
    out = out "\"github_release\":" json_str(github_release "/releases/tag/v" v) ","
    out = out "\"docs\":" json_str(docs_url) ","
    out = out "\"schema\":" json_url(schema[v]) ","
    out = out "\"artifacts\":{"
    out = out "\"windows\":{"
    out = out "\"win32_exe\":" json_url(windows[v, "win32_exe"]) ","
    out = out "\"win32_zip\":" json_url(windows[v, "win32_zip"]) ","
    out = out "\"win64_exe\":" json_url(windows[v, "win64_exe"]) ","
    out = out "\"win64_zip\":" json_url(windows[v, "win64_zip"]) ","
    out = out "\"winarm64_exe\":" json_url(windows[v, "winarm64_exe"]) ","
    out = out "\"winarm64_zip\":" json_url(windows[v, "winarm64_zip"])
    out = out "},"
    out = out "\"macos\":{"
    out = out "\"pkg\":" json_url(macos_pkg[v]) ","
    out = out "\"dmg\":" json_url(macos_dmg[v])
    out = out "},"
    out = out "\"linux\":["
    for (i = 1; i <= linux_count[v]; i++) {
        if (i > 1) {
            out = out ","
        }
        out = out "{"
        out = out "\"repo\":" json_str(linux_repo[v, i]) ","
        out = out "\"name\":" json_str(linux_name[v, i]) ","
        out = out "\"label\":" json_str(linux_lbl[v, i]) ","
        out = out "\"url\":" json_url(linux_path[v, i])
        out = out "}"
    }
    out = out "]},"
    out = out "\"linux_repos\":["
    repos_n = 0
    for (repo_key in linux_repo_set) {
        split(repo_key, parts, SUBSEP)
        if (parts[1] != v) {
            continue
        }
        if (repos_n++ > 0) {
            out = out ","
        }
        out = out json_str(base_url "/" parts[2])
    }
    out = out "]}"
    print v "\t" out
}

{
    if (NF < 1 || $0 == "") {
        next
    }

    path = $0
    sub(/\r$/, "", path)
    n = split(path, parts, "/")
    name = parts[n]

    if (name ~ /^fluent-bit-schema-[0-9]+\.[0-9]+(\.[0-9]+)*\.json$/) {
        v = schema_version(name)
        if (is_version(v)) {
            versions[v] = 1
            schema[v] = path
        }
        next
    }

    if (path ~ /^windows\//) {
        v = extract_version(name)
        key = windows_key(name, v)
        if (key != "") {
            versions[v] = 1
            windows[v, key] = path
        }
        next
    }

    if (path ~ /^macos\//) {
        v = extract_version(name)
        if (v == "") {
            next
        }
        versions[v] = 1
        if (name == "fluent-bit-" v ".pkg") {
            macos_pkg[v] = path
        } else if (name == "fluent-bit-" v ".dmg") {
            macos_dmg[v] = path
        }
        next
    }

    if (is_downloadable_linux(name)) {
        repo = repo_prefix(path)
        if (!is_canonical_linux_path(path, repo)) {
            next
        }
        v = extract_version(name)
        if (!is_version(v)) {
            next
        }
        versions[v] = 1
        note_linux(v, path, name, repo)
    }
}

END {
    mode = emit_mode
    for (v in versions) {
        if (!is_version(v)) {
            continue
        }
        if (mode == "versions") {
            emit_version(v)
        } else {
            print v
        }
    }
}
