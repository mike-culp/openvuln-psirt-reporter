def classify_advisory_products(product_names, product_groups):
    """
    Match an advisory's product names against the configured product groups.
    """
    matched_groups = set()
    friendly_products = set()

    if not product_names:
        return {
            "matched_groups": [],
            "friendly_products": [],
        }

    for group_key, group_config in product_groups.items():
        products = group_config.get("products", {})

        for friendly_name, product_config in products.items():
            match_terms = product_config.get("match", [])
            exclude_terms = product_config.get("exclude", [])

            product_matched = False

            for product_name in product_names:
                product_name_lower = product_name.lower()

                matches_product = any(
                    match_term.lower() in product_name_lower
                    for match_term in match_terms
                )

                excluded_from_product = any(
                    exclude_term.lower() in product_name_lower
                    for exclude_term in exclude_terms
                )

                if matches_product and not excluded_from_product:
                    product_matched = True
                    break

            if product_matched:
                matched_groups.add(group_key)
                friendly_products.add(friendly_name)

    return {
        "matched_groups": sorted(matched_groups),
        "friendly_products": sorted(friendly_products),
    }


def classify_all_advisories(advisories, product_groups):
    """
    Classify every advisory using the configured product groups.
    """
    classified_advisories = []

    for advisory in advisories:
        product_names = advisory.get("productNames", [])

        if isinstance(product_names, str):
            product_names = [product_names]
        elif not isinstance(product_names, list):
            product_names = [str(product_names)]

        classification = classify_advisory_products(product_names, product_groups)

        advisory_with_classification = advisory.copy()
        advisory_with_classification["matched_groups"] = classification["matched_groups"]
        advisory_with_classification["friendly_products"] = classification["friendly_products"]

        classified_advisories.append(advisory_with_classification)

    return classified_advisories