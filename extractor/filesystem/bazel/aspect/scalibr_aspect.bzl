"""Bazel aspect for extracting dependency metadata from the build graph."""

ScalibrInfo = provider(
    doc = "Provider for Scalibr dependency extraction info.",
    fields = {
        "files": "Depset of JSON metadata files.",
    },
)

def _scalibr_aspect_impl(target, ctx):
    """Aspect implementation that traverses dependencies and collects package metadata.

    Args:
        target: The target the aspect is applied to.
        ctx: The rule context.

    Returns:
        A list of providers (ScalibrInfo and OutputGroupInfo).
    """

    # We care about external workspaces, or internal targets that explicitly declare rules_license metadata
    is_external = bool(target.label.workspace_name)
    has_package_meta = hasattr(ctx, "rule") and hasattr(ctx.rule.attr, "package_name") and ctx.rule.attr.package_name

    transitive_files = []

    if hasattr(ctx, "rule") and hasattr(ctx.rule, "attr"):
        for attr_name in dir(ctx.rule.attr):
            attr_val = getattr(ctx.rule.attr, attr_name)
            if type(attr_val) == "list":
                for item in attr_val:
                    if type(item) == "Target" and ScalibrInfo in item:
                        transitive_files.append(item[ScalibrInfo].files)
            elif type(attr_val) == "Target":
                if ScalibrInfo in attr_val:
                    transitive_files.append(attr_val[ScalibrInfo].files)

    direct_files = []
    if is_external or has_package_meta:
        info = {
            "kind": ctx.rule.kind if hasattr(ctx, "rule") else "unknown",
            "label": str(target.label),
            "name": target.label.workspace_name,
        }

        # Try to gather common versioning and url attributes, including rules_license standard PackageInfo attributes
        if hasattr(ctx, "rule"):
            for attr in ["version", "tag", "commit", "url", "urls", "strip_prefix", "remote", "package_name", "package_version", "package_url"]:
                if hasattr(ctx.rule.attr, attr):
                    val = getattr(ctx.rule.attr, attr)
                    if val:
                        info[attr] = str(val)

        safe_name = target.label.name.replace("/", "_").replace(":", "_") + "-" + str(hash(str(target.label))) + ".scalibr.json"
        out_file = ctx.actions.declare_file(safe_name)
        ctx.actions.write(out_file, json.encode(info))
        direct_files.append(out_file)

    files_depset = depset(direct = direct_files, transitive = transitive_files)

    return [
        ScalibrInfo(files = files_depset),
        OutputGroupInfo(scalibr_out = files_depset),
    ]

# We traverse all attributes that can contain labels
scalibr_aspect = aspect(
    doc = "Aspect that collects dependency metadata for Scalibr.",
    implementation = _scalibr_aspect_impl,
    attr_aspects = ["*"],
)
