def _scalibr_aspect_impl(target, ctx):
    # We care about external workspaces, or internal targets that explicitly declare rules_license metadata
    is_external = bool(target.label.workspace_name)
    has_package_meta = hasattr(ctx, "rule") and hasattr(ctx.rule.attr, "package_name") and ctx.rule.attr.package_name

    if is_external or has_package_meta:
        info = {
            "name": target.label.workspace_name,
            "label": str(target.label),
            "kind": ctx.rule.kind if hasattr(ctx, "rule") else "unknown",
        }

        # Try to gather common versioning and url attributes, including rules_license standard PackageInfo attributes
        if hasattr(ctx, "rule"):
            for attr in ["version", "tag", "commit", "url", "urls", "strip_prefix", "remote", "package_name", "package_version", "package_url"]:
                if hasattr(ctx.rule.attr, attr):
                    val = getattr(ctx.rule.attr, attr)
                    if val:
                        info[attr] = str(val)

        # Emit the JSON with a unique prefix so the Go code can parse it from stderr
        print("SCALIBR_ASPECT_DATA::" + json.encode(info))

    return []

# Cache buster to force re-evaluation of the aspect

# We traverse all attributes that can contain labels
scalibr_aspect = aspect(
    implementation = _scalibr_aspect_impl,
    attr_aspects = ["*"],
)
