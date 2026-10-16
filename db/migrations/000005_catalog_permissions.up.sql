BEGIN;

-- Definitions only. No users or roles receive grants automatically.
INSERT INTO identity_permissions (resource, action, description)
VALUES
    ('catalog.categories', 'read', 'Catalog categories read'),
    ('catalog.categories', 'create', 'Catalog categories create'),
    ('catalog.categories', 'update', 'Catalog categories update'),
    ('catalog.brands', 'read', 'Catalog brands read'),
    ('catalog.brands', 'create', 'Catalog brands create'),
    ('catalog.brands', 'update', 'Catalog brands update'),
    ('catalog.units', 'read', 'Catalog units read'),
    ('catalog.units', 'create', 'Catalog units create'),
    ('catalog.units', 'update', 'Catalog units update'),
    ('catalog.products', 'read', 'Catalog products read'),
    ('catalog.products', 'create', 'Catalog products create'),
    ('catalog.products', 'update', 'Catalog products update'),
    ('catalog.product-variants', 'read', 'Catalog product-variants read'),
    ('catalog.product-variants', 'create', 'Catalog product-variants create'),
    ('catalog.product-variants', 'update', 'Catalog product-variants update'),
    ('catalog.attributes', 'read', 'Catalog attributes read'),
    ('catalog.attributes', 'create', 'Catalog attributes create'),
    ('catalog.attributes', 'update', 'Catalog attributes update'),
    ('catalog.attribute-values', 'read', 'Catalog attribute-values read'),
    ('catalog.attribute-values', 'create', 'Catalog attribute-values create'),
    ('catalog.attribute-values', 'update', 'Catalog attribute-values update'),
    ('catalog.variant-values', 'read', 'Catalog variant-values read'),
    ('catalog.variant-values', 'create', 'Catalog variant-values create'),
    ('catalog.variant-values', 'update', 'Catalog variant-values update'),
    ('catalog.product-images', 'read', 'Catalog product-images read'),
    ('catalog.product-images', 'create', 'Catalog product-images create'),
    ('catalog.product-images', 'update', 'Catalog product-images update'),
    ('catalog.price-lists', 'read', 'Catalog price-lists read'),
    ('catalog.price-lists', 'create', 'Catalog price-lists create'),
    ('catalog.price-lists', 'update', 'Catalog price-lists update'),
    ('catalog.prices', 'read', 'Catalog prices read'),
    ('catalog.prices', 'create', 'Catalog prices create'),
    ('catalog.prices', 'update', 'Catalog prices update')
ON CONFLICT (resource, action) DO NOTHING;

COMMIT;
