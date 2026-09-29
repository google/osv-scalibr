"""Bazel aspect for extracting dependency metadata from the build graph."""

ScalibrInfo = provider(
    doc = "Provider for Scalibr dependency extraction info.",
    fields = {
        "files": "Depset of JSON metadata files.",
    },
)

# Rule attributes copied into the metadata file when present.
_METADATA_ATTRS = [
    "version",
    "tag",
    "commit",
    "url",
    "urls",
    "strip_prefix",
    "remote",
    # rules_license package_info attributes.
    "package_name",
    "package_version",
    "package_url",
    # aspect_rules_js npm_package_internal attribute holding the npm package name.
    "package",
]

# Tag prefixes that carry package coordinates, mapped to the metadata key they're stored under.
_METADATA_TAG_PREFIXES = {
    # rules_jvm_external: "maven_coordinates=group:artifact:version".
    "maven_coordinates=": "maven_coordinates",
    # rules_python whl_library targets: "pypi_name=numpy", "pypi_version=1.26.4".
    "pypi_name=": "pypi_name",
    "pypi_version=": "pypi_version",
}

def _is_tool_configuration(ctx):
    """Returns whether the aspect is evaluating a target built for the exec configuration.

    Targets in the exec configuration are build tools (compilers, code generators, ...) rather
    than dependencies of the software being built. Starlark doesn't expose the configuration
    kind, so this checks the output directory name, as rules_license does.

    Args:
        ctx: The aspect context.

    Returns:
        True if the target is built for the exec configuration.
    """
    return "-exec" in ctx.bin_dir.path

def _collect_transitive_files(ctx):
    """Collects the metadata files of the target's user-declared dependencies.

    Args:
        ctx: The aspect context.

    Returns:
        A list of depsets of metadata files.
    """
    transitive_files = []
    for attr_name in dir(ctx.rule.attr):
        # Attributes starting with "_" are implicit dependencies added by the rule itself, such
        # as toolchains and helper binaries, not dependencies declared by the user.
        if attr_name.startswith("_"):
            continue
        attr_val = getattr(ctx.rule.attr, attr_name)
        deps = attr_val if type(attr_val) == "list" else [attr_val]
        for dep in deps:
            if type(dep) == "Target" and ScalibrInfo in dep:
                transitive_files.append(dep[ScalibrInfo].files)
    return transitive_files

def _metadata(target, ctx):
    """Returns the metadata recorded for the target.

    Args:
        target: The target the aspect is applied to.
        ctx: The aspect context.

    Returns:
        A dict of metadata values.
    """
    info = {
        "kind": ctx.rule.kind,
        "label": str(target.label),
        "name": target.label.workspace_name,
    }
    for attr in _METADATA_ATTRS:
        val = getattr(ctx.rule.attr, attr, None)
        if val:
            info[attr] = str(val)
    for tag in getattr(ctx.rule.attr, "tags", []):
        for prefix, key in _METADATA_TAG_PREFIXES.items():
            if tag.startswith(prefix):
                info[key] = tag[len(prefix):]
    return info

def _scalibr_aspect_impl(target, ctx):
    """Aspect implementation that traverses dependencies and collects package metadata.

    Args:
        target: The target the aspect is applied to.
        ctx: The aspect context.

    Returns:
        A list of providers (ScalibrInfo and OutputGroupInfo).
    """
    if _is_tool_configuration(ctx):
        empty = depset()
        return [
            ScalibrInfo(files = empty),
            OutputGroupInfo(scalibr_out = empty),
        ]

    # We care about external workspaces, or internal targets that explicitly declare rules_license
    # metadata.
    is_external = bool(target.label.workspace_name)
    has_package_meta = bool(getattr(ctx.rule.attr, "package_name", None))

    direct_files = []
    if is_external or has_package_meta:
        safe_name = target.label.name.replace("/", "_").replace(":", "_") + "-" + str(hash(str(target.label))) + ".scalibr.json"
        out_file = ctx.actions.declare_file(safe_name)
        ctx.actions.write(out_file, json.encode(_metadata(target, ctx)))
        direct_files.append(out_file)

    files_depset = depset(direct = direct_files, transitive = _collect_transitive_files(ctx))

    return [
        ScalibrInfo(files = files_depset),
        OutputGroupInfo(scalibr_out = files_depset),
    ]

# We traverse all attributes that can contain labels.
scalibr_aspect = aspect(
    doc = "Aspect that collects dependency metadata for Scalibr.",
    implementation = _scalibr_aspect_impl,
    attr_aspects = ["*"],
)
