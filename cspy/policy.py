POLICY_DIRECTIVES: set[str] = {
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "worker-src",
}


def override_policy_directives(directives: set[str]) -> None:
    """Add one or more policy directives to the supported list

    Args:
        directives (set[str]): A set of policy directives to add
    """

    global POLICY_DIRECTIVES
    POLICY_DIRECTIVES.update({directive.lower() for directive in directives})


def parse_serialized_csp(policy: str, strict: bool = False) -> dict[str, list[str]]:
    """Parse a serialized Content Security Policy

    Args:
        policy (str): The police to parse
        strict (bool, optional): Whether or not to raise an exception for duplicate
        directives. Defaults to False.

    Raises:
        ValueError: An unknown directive was encountered
        ValueError: A duplicate directive was encountered

    Returns:
        dict[str, list[str]]: A mapping of policy directives to one or more values
    """

    result: dict[str, list[str]] = {}

    # For each token returned by strictly splitting serialized on the U+003B SEMICOLON
    # character (;):
    for token in policy.split(";"):
        # 1. Strip leading and trailing ASCII whitespace from token.
        token = token.strip()

        # 2. If token is an empty string, or if token is not an ASCII string, continue.
        if not token or not token.isascii():
            continue

        # We do these at the same time:
        # 3. Let directive name be the result of collecting a sequence of
        #    code points from token which are not ASCII whitespace.
        # 6. Let directive value be the result of splitting token on
        #    ASCII whitespace.
        split_token = token.split()
        raw_directive_name, directive_value = split_token[0], split_token[1:]

        # 4. Set directive name to be the result of running ASCII lowercase on
        #    directive name.
        directive_name = raw_directive_name.lower()

        if directive_name not in POLICY_DIRECTIVES:
            raise ValueError(f"unknown directive '{directive_name}'")

        # 5. If policy's directive set contains a directive whose name is
        #    directive name, continue.
        if directive_name in result:
            if strict:
                raise ValueError(f"duplicate directive '{directive_name}'")

            continue

        # 7. Let directive be a new directive whose name is directive name, and
        #    value is directive value.
        # 8. Append directive to policy's directive set.
        result[directive_name] = directive_value

    return result
